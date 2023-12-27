#include "localcongestionlimiter_filter.h"
#include "congestionlimitengine.h"
#include "responseengine.h"
#include "common/router/router_ratelimit.h"
#include "envoy/stats/scope.h"
#include "common/common/logger.h"
#include "common/http/utility.h"
#include <numeric>

namespace Envoy {
namespace Http {
namespace CongestionLimiter {

// Makes an unowned ratelimitpolicy pointer from a LocalCongestionLimit proto
Envoy::Router::RateLimitPolicyEntry* LocalCongestionLimiterConfig::makeRateLimitPolicy(
    const filter_protos::LocalCongestionLimit& proto_limit, Server::Configuration::FactoryContext& context) {
  envoy::config::route::v3::RateLimit ratelimit{};
  // TODO<kburek> is there a zero-copy way of getting an appropriate RateLimit protobuf?
  for (auto d : proto_limit.descriptor_components()) {
    ratelimit.add_actions()->CopyFrom(d);
  }
  return new Envoy::Router::RateLimitPolicyEntryImpl(ratelimit, context.messageValidationVisitor());
}

LocalCongestionLimiter::LocalCongestionLimiter(LocalCongestionLimiterConfigSharedPtr config)
    : config_(config),
      stats_prefix_(Envoy::statPrefixJoin(config->getStatsPrefix(), "edge_localcongestionlimiter")),
      // stat_prefix_(std::make_unique<Stats::StatNameDynamicStorage>(config->getStatsPrefix(), config->getScope().symbolTable()),
      stream_destroyed_(false) {}

Http::FilterHeadersStatus LocalCongestionLimiter::decodeHeaders(Http::RequestHeaderMap& headers, bool) {
  ASSERT(config_ != nullptr);

  if (!config_->isFilterEnabled()) {
    ENVOY_STREAM_LOG(trace, "Congestionlimiter filter is disabled", *decoder_callbacks_);
    return Http::FilterHeadersStatus::Continue;
  }

  if (localcongestionlimiter_checks_complete_) {
    config_->stats().localcongestionlimiter_checks_duplicate_call_.inc();
    return Http::FilterHeadersStatus::Continue;
  }

  localcongestionlimiter_checks_complete_ = true;

  ENVOY_STREAM_LOG(
      debug,
      "LocalCongestionLimiter checking request: remoteAddress: {}, "
                                               "localAddress: {}, "
                                               "headers: {} ",
      *decoder_callbacks_,
      decoder_callbacks_->connection()->addressProvider().remoteAddress()->asString(),
      decoder_callbacks_->connection()->addressProvider().localAddress()->asString(),
      headers);

  // Run RateLimiter Actions to build descriptor
  // Get all descriptors for limit policy entries for the request
  Engine::RequestDescription description;
  ASSERT(config_->getRateLimitPolicy().get() != nullptr);

  config_->getRateLimitPolicy()->populateDescriptors(description,
                                                     config_->localInfo().clusterName(),
                                                     headers,
                                                     decoder_callbacks_->streamInfo());

  auto limit_stats_prefix = Envoy::statPrefixJoin(stats_prefix_, config_->getLimitName());
  config_->getScope()
      .counterFromString(Envoy::statPrefixJoin(limit_stats_prefix, "described"))
      .inc();

  // If no descriptors generated, return Http::FilterHeadersStatus::Continue
  int entry_count =
      std::transform_reduce(description.begin(), description.end(), 0, std::plus{},
                            [](Envoy::RateLimit::Descriptor d) { return d.entries_.size(); });
  config_->stats().localcongestionlimiter_descriptor_entry_count_.add(entry_count);
  if (description.empty()) {
    config_->stats().localcongestionlimiter_generated_empty_descriptors_.inc();
    return Http::FilterHeadersStatus::Continue;
  }

  // Choose Limit by matching descriptor
  std::vector<Engine::LimitToCheck> limits =
      config_->limitEngine().constructLimitsToCheck(std::string(config_->getLimitName()), description);

  // If no limit matched, return Http::FilterHeadersStatus::Continue
  const bool no_limits_matched = 
      std::none_of(limits.begin(), limits.end(),
                   [](auto l) { return l.rateLimit.lock() != nullptr; });
  if (no_limits_matched) {
    config_->stats().localcongestionlimiter_descriptors_hit_no_limits_.inc();
    return Http::FilterHeadersStatus::Continue;
  }

  // Charge limits, get decision
  bool shouldProceed = true;
  for (auto& limit_to_check : limits) {
    if (Engine::DescriptorLimitPtr descriptorLimit = limit_to_check.rateLimit.lock()) {
      config_->stats().limit_hit_.inc();
      if (limit_to_check.isUnlimited) {
        continue;
      }

      if (descriptorLimit->Limit) {
        auto decision = descriptorLimit->Limit->shouldProceed();
        if (decision.shouldProceed) {
          // Save allowed limits for decrement in encode path.
          limit_to_check.countWhenChecked = decision.count;
          limits_hit_.push(limit_to_check);
        } else {
          // Unwind previously allowed limits since !shouldProceed.
          // TODO<kburek> There's an edge case here for monitor actions.
          //              Over-limit monitor actions will let a request
          //              flow upstream even though we unwound other
          //              matching limits. The monitor will effectively
          //              disable other limits that might have applied.
          while (!limits_hit_.empty()) {
            if(auto limiter_to_unwind = limits_hit_.top().rateLimit.lock()) {
              limiter_to_unwind->Limit->releaseInflight();
            }
            limits_hit_.pop();
          }
          shouldProceed = false;
          break;
        }
      } else {
        ENVOY_STREAM_LOG(error, "missing limit impl: {}", *decoder_callbacks_, descriptorLimit->Name);
      }
    }
  }

  if (shouldProceed) {
    // If limit decision is Proceed, return Http::FilterHeadersStatus::Continue
    config_->getScope()
        .counterFromString(Envoy::statPrefixJoin(limit_stats_prefix, "under_limit"))
        .inc();
    setStartTime(std::chrono::steady_clock::now());
    return Http::FilterHeadersStatus::Continue;
  } else {
    config_->getScope()
        .counterFromString(Envoy::statPrefixJoin(limit_stats_prefix, "over_limit"))
        .inc();
  }

  // Limit decision was not proceed: Access and invoke Response Policy.
  Http::FilterHeadersStatus decodeHeadersResult = matchAndSendLocalResponse(headers);
  setStartTime(std::chrono::steady_clock::now());
  return decodeHeadersResult;
}

namespace {
  bool isDropped(const ::Envoy::Http::ResponseHeaderMap& headers) {
    absl::string_view received_response_status = headers.getStatusValue();
    uint32_t int_status;
    if (!absl::SimpleAtoi(received_response_status, &int_status)) {
      int_status = 0;
    };

    // If upstream dropped the request or gateway timeout
    // occurs then we get local reply of HTTP 503/504
    return int_status == 503 || int_status == 504;
  }
}

Http::FilterHeadersStatus LocalCongestionLimiter::matchAndSendLocalResponse(Http::RequestHeaderMap& headers) {
  ASSERT(decoder_callbacks_ != nullptr);
  ASSERT(config_ != nullptr);
  ASSERT(config_->responseEngine().getPolicyName() != "");
  // Increment the policy counter, whether it will match and act or not.
  auto policy_stats_prefix =
      Envoy::statPrefixJoin(stats_prefix_, config_->responseEngine().getPolicyName());
  config_->getScope().counterFromString(policy_stats_prefix).inc();

  // Sanity check for connection
  auto* connection = decoder_callbacks_->connection();
  if (connection == nullptr) {
    config_->stats().localcongestionlimiter_response_policy_no_connection_.inc();
    return Http::FilterHeadersStatus::Continue;
  }

  Envoy::Http::CBMatcher::Context context{*connection, headers};
  auto matchedAction = config_->responseEngine().getMatchingRule(context);
  if (!matchedAction.has_value()) {
    config_->getScope()
        .counterFromString(Envoy::statPrefixJoin(policy_stats_prefix, "no_match"))
        .inc();
    return Http::FilterHeadersStatus::Continue;
  }

  auto action = config_->responseEngine().getAction(matchedAction.value());
  ASSERT(action != nullptr);
  config_->getScope()
      .counterFromString(Envoy::statPrefixJoin(policy_stats_prefix, action->getActionName()))
      .inc();
  // TODO<kburek>: stream metadata for action executed
  return action->execute(*connection, headers, decoder_callbacks_);
}

Http::FilterHeadersStatus LocalCongestionLimiter::encodeHeaders(Http::ResponseHeaderMap& headers, bool) {
  if (!config_->isFilterEnabled()) {
    return Http::FilterHeadersStatus::Continue;
  }
  bool did_drop = isDropped(headers);
  auto start_time = getStartTime();
  auto rtt = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start_time);
  // Feed back this request to the policy to learn and adjust the limit
  while (!limits_hit_.empty()) {
    auto limit_hit = limits_hit_.top();
    if (auto limiter_hit = limit_hit.rateLimit.lock()) {
      limiter_hit->Limit->onSample(start_time, rtt, limit_hit.countWhenChecked, did_drop);
      limiter_hit->Limit->releaseInflight();
    }
    limits_hit_.pop();
  }

  return Http::FilterHeadersStatus::Continue;
}

} // namespace CongestionLimiter
} // namespace Http
} // namespace Envoy
