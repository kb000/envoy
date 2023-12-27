#pragma once

#include "envoy/config/filter/http/localcongestionlimiter_filter/v3/localcongestionlimiter_filter.pb.h"
#include "envoy/config/filter/http/localcongestionlimiter_filter/v3/localcongestionlimiter_filter.pb.validate.h"
#include "envoy/config/filter/http/circuitbreaker_filter/v3/circuitbreaker_filter.pb.h"
#include "envoy/config/filter/http/circuitbreaker_filter/v3/circuitbreaker_filter.pb.validate.h"

#include <string_view>
#include "actions/actions.h"
#include "circuitbreaker/limit.h"
#include "matchers/context.h"
#include "matchers/matchers.h"
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
namespace Engine {

class ResponseEngine;
namespace filter_protos = envoy::config::filter::http::localcongestionlimiter_filter::v3;
typedef std::shared_ptr<ResponseEngine> ResponseEngineSharedPtr;
typedef filter_protos::Responsepolicy_MatchAction MatchAction;
typedef OptRef<const filter_protos::Responsepolicy_MatchAction> MatchActionOptRef;

class ResponseEngine : public Logger::Loggable<Logger::Id::filter> {
public:
  ResponseEngine(const filter_protos::Responsepolicy& policy, Server::Configuration::FactoryContext& context);

  const std::string getPolicyName() const {
    return policy_name_;
  }

  MatchActionOptRef getMatchingRule(const Envoy::Http::CBMatcher::Context& requestContext);

  Envoy::Http::Action::ActionConstSharedPtr getAction(const MatchAction& actionConfig);

  const std::string policy_name_;
  const std::vector<std::pair<MatcherConstSharedPtr, MatchAction>> rules_;
  Server::Configuration::FactoryContext& context_;
};

} // namespace Engine
} // namespace CongestionLimiter
} // namespace Http
} // namespace Envoy
