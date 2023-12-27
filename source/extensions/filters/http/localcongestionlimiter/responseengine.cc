#include "responseengine.h"
#include "matchers/matchers.h"

namespace Envoy {
namespace Http {
namespace CongestionLimiter {
namespace Engine {

namespace {
std::vector<std::pair<MatcherConstSharedPtr, MatchAction>> createRules(const filter_protos::Responsepolicy& policy) {
  std::vector<std::pair<MatcherConstSharedPtr, MatchAction>> rules;
  for (const auto& response : policy.responses()) {
    rules.emplace_back(Envoy::CBMatcher::create(response.match()), response);
  }
  return rules;
}
} // namespace

/**
 * @brief Constructs a ResponseEngine from a proto configuration.
 *
 * @param policy The proto configuration.
 * @param context The factory context.
 */
ResponseEngine::ResponseEngine(const filter_protos::Responsepolicy& policy, Server::Configuration::FactoryContext& context)
    : policy_name_(policy.name()), rules_(createRules(policy)), context_(context) {}

/**
 * @brief Returns the first matching rule for a given request context.
 * 
 * @param requestContext The request context.
 * @return MatchActionOptRef The matching rule, if any.
 */
MatchActionOptRef ResponseEngine::getMatchingRule(const Envoy::Http::CBMatcher::Context& requestContext) {
  for (const auto& rule : rules_) {
    if (rule.first->matches(requestContext)) {
      return MatchActionOptRef{rule.second};
    }
  }
  return MatchActionOptRef{};
}

Envoy::Http::Action::ActionConstSharedPtr ResponseEngine::getAction(const MatchAction& actionConfig) {
  ENVOY_LOG(debug, "ResponseEngine creating action {}", actionConfig.DebugString());
  return Envoy::Http::Action::ActionBaseImpl::create(actionConfig.action(), context_);
}

} // namespace Engine
} // namespace CongestionLimiter
} // namespace Http
} // namespace Envoy
