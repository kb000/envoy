#include "congestionlimitengine.h"
#include "common/router/router_ratelimit.h"
#include "envoy/stats/scope.h"
#include "common/common/logger.h"
#include "common/http/utility.h"
#include <numeric>

namespace Envoy {
namespace Http {
namespace CongestionLimiter {
namespace Engine {

namespace {
  std::string debugString(const Envoy::RateLimit::Descriptor& descriptor) {
    std::string result = "{";
    for (auto& entry : descriptor.entries_) {
      result += entry.key_ + "=" + entry.value_ + ",";
    }
    result += "}";
    return result;
  }
}


/**
 * @brief Finds limits that match a request description.
 *
 * @param request A list of descriptor instances which describe a request.
 * @return A list of the same length of limits to check, perhaps having no actual limiter attached.
 *
 * @see https://github.com/envoyproxy/ratelimit/blob/c97749cc2d2d9e453aa7b7fc08b86cbe22a031e8/src/service/ratelimit.go#L113
 */
std::vector<LimitToCheck> CongestionLimitEngine::constructLimitsToCheck(const std::string& limiterName, const RequestDescription& request) {
  std::vector<LimitToCheck> limitsToCheck{};

  std::unordered_set<std::string> replacing;

  for (auto& descriptorInstance : request) {
    // TODO(kburek)[UFES-8081] Debug log descriptorInstance
    ENVOY_LOG(trace, "Checking Descriptor {}", debugString(descriptorInstance));
    LimitToCheck limit{};
    limit.rateLimit = getLimit(limiterName, descriptorInstance);
    if (auto rateLimit = limit.rateLimit.lock()) {
      for (auto replace : rateLimit->Replaces) {
        replacing.insert(replace);
      }

      if (rateLimit->Unlimited) {
        limit.isUnlimited = true;
        limit.rateLimit.reset();
      }
    }
    limitsToCheck.push_back(std::move(limit));
  }

  for (auto& limit : limitsToCheck) {
    if (auto rateLimit = limit.rateLimit.lock()) {
      if (rateLimit->Name.empty()) {
        continue;
      }
      if (replacing.find(rateLimit->Name) != replacing.end()) {
        ENVOY_LOG(debug, "Replacing Limit {}", rateLimit->Name);
        limit.rateLimit.reset();
      }
    }
  }

  return limitsToCheck;
}

/**
 * @brief Finds a single limit matched by a descriptor instance.
 *
 * @see https://github.com/envoyproxy/ratelimit/blob/c97749cc2d2d9e453aa7b7fc08b86cbe22a031e8/src/config/config_impl.go#L279
 */
DescriptorLimitRef CongestionLimitEngine::getLimit(const std::string& limiterName, const Envoy::RateLimit::Descriptor& descriptorInstance) const {

  ENVOY_LOG(debug, "starting get limit lookup");
  DescriptorLimitRef limit{};

  auto limiterPair = limiters_.find(limiterName);
  if (limiters_.end() == limiterPair) {
    ENVOY_LOG(debug, "unknown limiter '{}'", limiterName);
    return limit;
  }

  // Local Congestion Limiter descriptors do not have override limits. Assert that the limit_ member is empty.
  ASSERT(!descriptorInstance.limit_.has_value());

  auto& limiter = limiterPair->second;
  auto& entries = descriptorInstance.entries_;
  auto const* descriptorsMap = &limiter.descriptors;
  rateLimitDescriptorNode const* prevDescriptor = &limiter;
  for (size_t i = 0; i < entries.size(); i++) {
    // Don't even try if we have an empty map.
    if (descriptorsMap->empty()) {
      break;
    }

    // First see if key_value is in the map.
    std::string finalKey = entries[i].key_ + "_" + entries[i].value_;
    ENVOY_LOG(debug, "Matching by descriptor key_value: {}", finalKey);
    auto nextDescriptor = descriptorsMap->find(finalKey);

    // Didn't find key/value in the map. Check for wildcard match.
    if (nextDescriptor == descriptorsMap->end() && !prevDescriptor->wildcardKeys.empty()) {
      ENVOY_LOG(debug, "Matching wildcards by descriptor key_value: {}", finalKey);
      for (auto& wildcardKey : prevDescriptor->wildcardKeys) {
        int wildcardSize = wildcardKey.size() > 0 && wildcardKey.back() == '*'
                               ? wildcardKey.size() - 1
                               : wildcardKey.size();
        if (finalKey.compare(0, wildcardSize, wildcardKey) == 0) {
          nextDescriptor = descriptorsMap->find(wildcardKey);
          break;
        }
      }
    }

    // Did not find key/value or matching wildcard. Try just key (implicit default / match-all value).
    if (nextDescriptor == descriptorsMap->end()) {
      finalKey = entries[i].key_;
      ENVOY_LOG(debug, "Matching by descriptor key: {}", finalKey);
      nextDescriptor = descriptorsMap->find(finalKey);
    }

    // Did not find descriptor in map by any matching method.
    if (nextDescriptor == descriptorsMap->end()) {
      break;
    }

    if (nextDescriptor->second.limit) {
      ENVOY_LOG(debug, "Matched descriptor to rate limit: {}", finalKey);

      if (i + 1 >= entries.size()) {
        if (nextDescriptor->second.limit) {
          limit = nextDescriptor->second.limit;
        }
      } else {
        ENVOY_LOG(
            debug,
            "Request descriptor length does not match config depth. "
            "Will continue to match more entries in the request's descriptor."
            );
      }
    }

    // Iterate to next level
    prevDescriptor = &nextDescriptor->second;
    descriptorsMap = &prevDescriptor->descriptors;
  }

  return limit;
}

const char WILDCARD_CHAR = '*';

/**
 * @brief Validates and builds limit counters for one node of a descriptor match tree
 *
 * @see https://github.com/envoyproxy/ratelimit/blob/c97749cc2d2d9e453aa7b7fc08b86cbe22a031e8/src/config/config_impl.go#L123
 */
void CongestionLimitEngine::loadDescriptors(rateLimitDescriptorNode& parent, const std::string& limitName, const std::string& parentKey, const google::protobuf::RepeatedPtrField<filter_protos::CongestionLimitDescriptor>& descriptors) {
  for (const filter_protos::CongestionLimitDescriptor& descriptorConfig : descriptors) {
    if (descriptorConfig.key().empty()) {
      // TODO(kburek)[UFES-8081]: Guard against and reject this config before filter chain instantiation.
      ENVOY_LOG(error, "Descriptor missing key in limit {}", limitName);
      continue;
    }

    // Value is optional, so the final key for the map is either the key only or key_value.
    std::string finalKey = descriptorConfig.key();
    if (!descriptorConfig.value().empty()) {
      finalKey.append("_");
      finalKey.append(descriptorConfig.value());
    }

    std::string newParentKey = parentKey + finalKey;
    if (parent.descriptors.find(finalKey) != parent.descriptors.end()) {
      // TODO(kburek)[UFES-8081] panic. Do we fail gracefully? Can we effect a config reject?
      ENVOY_LOG(error, "duplicate descriptor composite key '{}'", newParentKey);
      return;
    }

    rateLimitDescriptorNode newDescriptor{};

    if (descriptorConfig.has_limit()) {
      Circuitbreaker::LimitPtr limit =
          Envoy::Http::Circuitbreaker::LimitFactory::create(descriptorConfig.limit(), api_.randomGenerator());
      std::vector<std::string> replaces;
      // std::transform(descriptorConfig.replaces.begin(), descriptorConfig.replaces.end(),
      //                  std::back_inserter(replaces), [](filter_protos::LimitReplaces l) { return l.name; }));
      newDescriptor.limit = std::make_shared<DescriptorLimit>(descriptorConfig.limit(), std::move(limit));
      newDescriptor.limit->FullKey = newParentKey;
      newDescriptor.limit->Name = finalKey;
      newDescriptor.limit->Replaces = replaces;
      newDescriptor.limit->ShadowMode = descriptorConfig.shadow_mode();

      // TODO(kburek)[UFES-8081] verification and logs for below
      // for _, replaces := range descriptorConfig.RateLimit.Replaces {
      //  if replaces.Name == "" {
      //    panic(newRateLimitConfigError(config.Name, "should not have an empty replaces entry"))
      //  }
      //  if replaces.Name == descriptorConfig.RateLimit.Name {
      //    panic(newRateLimitConfigError(config.Name, "replaces should not contain name of same descriptor"))
      //  }
      //}
    }

    // TODO(kburek)[UFES-6934] stat for below:
    // logger.Debugf("loading descriptor: key=%s%s", newParentKey, rateLimitDebugString)
    loadDescriptors(
        newDescriptor, limitName, newParentKey + ".", descriptorConfig.descriptors());
    parent.descriptors[finalKey] = std::move(newDescriptor);

    // Preload keys ending with "*" symbol.
    if (finalKey.back() == WILDCARD_CHAR) {
      parent.wildcardKeys.push_back(finalKey);
    }
  }
}

/**
 * @brief Loads an entire config yaml into the limit engine.
 *
 * @see https://github.com/envoyproxy/ratelimit/blob/965f0bc861da0d4478071aeca0a5f2c2202257b7/src/config/config_impl.go#L246
 */
void CongestionLimitEngine::loadConfig(const filter_protos::LocalCongestionLimit& config) {
  if (config.name().empty()) {
    // TODO(kburek) integration test this negative case results in config reject.
    throw EnvoyException(fmt::format("{} config cannot have empty name: {}", config.GetTypeName(), config.DebugString()));
    return;
  }

  std::string limiterName = config.name();
  auto limiterPair = limiters_.find(limiterName);
  if (limiters_.end() != limiterPair) {
    ENVOY_LOG(debug, "CongestionLimitEngine patching limiter: {}", limiterName);
    loadDescriptors(limiterPair->second, limiterName, limiterName + ".", config.descriptors());
    return;
  }

  ENVOY_LOG(debug, "CongestionLimitEngine loading new limiter: {}", limiterName);
  rateLimitDescriptorNode descriptorNode{};
  loadDescriptors(descriptorNode, limiterName, limiterName + ".", config.descriptors());
  limiters_[limiterName] = std::move(descriptorNode);
}

} // namespace Engine
} // namespace CongestionLimiter
} // namespace Http
} // namespace Envoy
