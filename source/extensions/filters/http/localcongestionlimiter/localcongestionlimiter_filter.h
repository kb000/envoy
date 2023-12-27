#pragma once

#include <memory>
#include <string_view>
#include "congestionlimitengine.h"
#include "responseengine.h"
#include "envoy/config/filter/http/localcongestionlimiter_filter/v3/localcongestionlimiter_filter.pb.h"
#include "envoy/config/filter/http/localcongestionlimiter_filter/v3/localcongestionlimiter_filter.pb.validate.h"
#include "envoy/config/filter/http/circuitbreaker_filter/v3/circuitbreaker_filter.pb.h"
#include "envoy/config/filter/http/circuitbreaker_filter/v3/circuitbreaker_filter.pb.validate.h"
#include "circuitbreaker/limit.h"
#include "fmt/format.h"
#include "envoy/http/filter.h"
#include "envoy/ratelimit/ratelimit.h"
#include "envoy/router/router_ratelimit.h"
#include "envoy/local_info/local_info.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "common/common/logger.h"
#include "envoy/common/random_generator.h"
#include "extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Http {
namespace CongestionLimiter {

#define FILTER_STATS(COUNTER)                                                                      \
  COUNTER(limit_hit)  // clang-format on

#define FILTER_DEBUG_STATS(COUNTER)                                                                \
  COUNTER(localcongestionlimiter_checks_duplicate_call)                                            \
  COUNTER(localcongestionlimiter_descriptor_entry_count)                                           \
  COUNTER(localcongestionlimiter_generated_empty_descriptors)                                      \
  COUNTER(localcongestionlimiter_descriptors_hit_no_limits)                                        \
  COUNTER(localcongestionlimiter_response_policy_no_connection)  // clang-format on

typedef std::unique_ptr<Envoy::Router::RateLimitPolicyEntry> RateLimitPolicyEntryPtr;
namespace filter_protos = envoy::config::filter::http::localcongestionlimiter_filter::v3;

struct CongestionlimiterStats {
  FILTER_STATS(GENERATE_COUNTER_STRUCT)
  FILTER_DEBUG_STATS(GENERATE_COUNTER_STRUCT)
};

namespace {
  template<typename T>
  const T& findByName(std::string_view name, const Protobuf::RepeatedPtrField<T>& list) {
    for (const auto& item : list) {
      if (item.name() == name) {
        return item;
      }
    }
    throw EnvoyException(fmt::format("Couldn't find {} in list", name));
  }
}


template <class ConfigType>
Engine::CongestionLimitEngineSharedPtr createLimitEngine(const ConfigType& proto_limit, Server::Configuration::FactoryContext& context) {
  // TODO(kburek): There could be one engine attached to each cluster, maybe?
  //   This (and CircuitBreakerFilter's) engine is per filter chain right now, so the limits aren't shared across routes :(
  auto engine = std::make_shared<Engine::CongestionLimitEngine>(context.api());
  engine->loadConfig(proto_limit);
  return engine;
}

template <class ConfigType>
Engine::ResponseEngineSharedPtr
createResponseEngine(const ConfigType& proto_response_policy, Server::Configuration::FactoryContext& context) {
  // Create a response engine that can iterate through proto_response_policy.responses for the right match.
  auto response_engine = std::make_shared<Engine::ResponseEngine>(proto_response_policy, context);
  return response_engine;
}

/**
 * Configuration for the Congestionlimiter filter.
 */
class LocalCongestionLimiterConfig {
public:
  LocalCongestionLimiterConfig(
    const filter_protos::LocalCongestionLimit& proto_limit,
    const filter_protos::LocalCongestionLimiter& proto_config,
    const std::string& stats_prefix, Stats::Scope& scope, Server::Configuration::FactoryContext& context)
      : stats_(generateStats(stats_prefix, scope)), stats_prefix_(stats_prefix),
        limit_name_(proto_limit.name()),
        rate_limit_policy_(makeRateLimitPolicy(proto_limit, context)),
        limit_engine_(createLimitEngine(proto_limit, context)),
        response_engine_(createResponseEngine(findByName(proto_limit.response_policy(), proto_config.response_policies()), context)),
        scope_(scope),
        local_info_(context.localInfo()), filter_enabled_(proto_config.filter_enabled()) {}

  const RateLimitPolicyEntryPtr& getRateLimitPolicy() const {
    return rate_limit_policy_;
  }
  CongestionlimiterStats& stats() { return stats_; }
  Engine::CongestionLimitEngine& limitEngine() { 
    ASSERT(limit_engine_ != nullptr);
    return *limit_engine_;
  };
  Engine::ResponseEngine& responseEngine() { 
    ASSERT(response_engine_ != nullptr);
    return *response_engine_;
  }
  const std::string_view getStatsPrefix() const { return stats_prefix_; }
  const std::string_view getLimitName() const { return limit_name_; }
  Stats::Scope& getScope() { return scope_; }
  const Envoy::LocalInfo::LocalInfo& localInfo() { return local_info_; }
  bool isFilterEnabled() const { return filter_enabled_; };

private:
  CongestionlimiterStats stats_;
  const std::string stats_prefix_;
  const std::string limit_name_;
  RateLimitPolicyEntryPtr rate_limit_policy_;
  Engine::CongestionLimitEngineSharedPtr limit_engine_;
  Engine::ResponseEngineSharedPtr response_engine_;
  Stats::Scope& scope_;
  const Envoy::LocalInfo::LocalInfo& local_info_;
  const bool filter_enabled_;

  static Envoy::Router::RateLimitPolicyEntry* makeRateLimitPolicy(const filter_protos::LocalCongestionLimit& proto_limit, Server::Configuration::FactoryContext& context);

  static CongestionlimiterStats generateStats(const std::string& prefix, Stats::Scope& scope) {
    return CongestionlimiterStats{
      FILTER_STATS(POOL_COUNTER_PREFIX(scope, prefix))
      FILTER_DEBUG_STATS(POOL_COUNTER_PREFIX(scope, prefix))
      };
  }
};

typedef std::shared_ptr<LocalCongestionLimiterConfig> LocalCongestionLimiterConfigSharedPtr;

/**
 * A filter that characterizes and rate-limits requests.
 */
class LocalCongestionLimiter : public Http::StreamFilter, public Logger::Loggable<Logger::Id::filter> {
public:
  LocalCongestionLimiter(LocalCongestionLimiterConfigSharedPtr config);

  void onDestroy() override {
    stream_destroyed_ = true;
    if (localcongestionlimiter_allowed_request_) {
      localcongestionlimiter_allowed_request_ = false;
      cancelRequest();
    }
  };

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers, bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override {
    if (stream_destroyed_) {
      return Http::FilterDataStatus::StopIterationAndWatermark;
    } else {
      return Http::FilterDataStatus::Continue;
    }
  }
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override {
    if (stream_destroyed_) {
      return Http::FilterTrailersStatus::StopIteration;
    } else {
      return Http::FilterTrailersStatus::Continue;
    }
  }
  Http::FilterMetadataStatus encodeMetadata(Http::MetadataMap&) override {
    return Http::FilterMetadataStatus::Continue;
  }
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override {
    decoder_callbacks_ = &callbacks;
  }

  // Http::StreamEncoderFilter
  Http::FilterHeadersStatus encode100ContinueHeaders(Http::ResponseHeaderMap&) override {
    return Http::FilterHeadersStatus::Continue;
  }
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap&, bool) override;
  Http::FilterDataStatus encodeData(Buffer::Instance&, bool) override {
    return Http::FilterDataStatus::Continue;
  }
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) override {
    encoder_callbacks_ = &callbacks;
  }

  // Support API for setting DynamicMetadata for access logging
  void populateProtoStructFromString(ProtobufWkt::Struct& obj, std::string key, std::string value);
  void populateProtoStructFromBool(ProtobufWkt::Struct& obj, std::string key, bool value);
  void setValueOnStreamInfo(std::string status, std::string key);

  // Start timestamp
  std::chrono::time_point<std::chrono::steady_clock>& getStartTime() {
    return start_time_;
  }
  void setStartTime(std::chrono::time_point<std::chrono::steady_clock> v) {
    start_time_ = v;
  }

  // Local response
  Http::FilterHeadersStatus matchAndSendLocalResponse(Http::RequestHeaderMap& headers);

private:
  void cancelRequest() {}

  LocalCongestionLimiterConfigSharedPtr config_;
  std::stack<Engine::LimitToCheck> limits_hit_;
  std::string stats_prefix_;
  bool stream_destroyed_;
  std::chrono::time_point<std::chrono::steady_clock> start_time_;
  int count_during_decode_;
  bool localcongestionlimiter_checks_complete_{false};
  bool localcongestionlimiter_allowed_request_{false};

  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{nullptr};
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_{nullptr};
};

} // namespace CongestionLimiter
} // namespace Http
} // namespace Envoy
