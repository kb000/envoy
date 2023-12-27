#pragma once

#include <memory>
#include <string_view>
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

namespace cb_protos = envoy::config::filter::http::circuitbreaker_filter::v3;
namespace filter_protos = envoy::config::filter::http::localcongestionlimiter_filter::v3;

namespace Envoy {
namespace Http {
namespace CongestionLimiter {
namespace Engine {

typedef std::vector<Envoy::RateLimit::Descriptor> RequestDescription;
typedef std::vector<filter_protos::CongestionLimitDescriptor> Descriptors;

struct DescriptorLimit {
  DescriptorLimit(const cb_protos::CBConfig& limitConfig,
                  std::unique_ptr<Envoy::Http::Circuitbreaker::Limit>&& limit)
      : Config(limitConfig), Limit(std::move(limit)) {}

  std::string FullKey;
  void* Stats;
  const cb_protos::CBConfig& Config;
  std::unique_ptr<Envoy::Http::Circuitbreaker::Limit> Limit;
  bool Unlimited;
  bool ShadowMode;
  std::string Name;
  std::vector<std::string> Replaces;
  bool IncludeValueInMetricWhenNotSpecified;
};

typedef std::shared_ptr<DescriptorLimit> DescriptorLimitPtr;
typedef std::weak_ptr<DescriptorLimit> DescriptorLimitRef;

// rateLimitDescriptorNodes form the descriptor tree.
//   This data structure owns the limit machinery.
struct rateLimitDescriptorNode {
  std::map<std::string, rateLimitDescriptorNode> descriptors;
  DescriptorLimitPtr limit;
  std::vector<std::string> wildcardKeys;
};

// LimitToCheck is temporary, it references the limits.
struct LimitToCheck {
  DescriptorLimitRef rateLimit;
  int countWhenChecked;
  // TODO(kburek): CBLimit doesn't have the option for unlimited. Either add the config or remove the code.
  bool isUnlimited;
};

class CongestionLimitEngine : public Logger::Loggable<Logger::Id::filter> {
public:
  CongestionLimitEngine(Envoy::Api::Api& api) :
    api_(api) {};

  void loadConfig(const filter_protos::LocalCongestionLimit& config);

  std::vector<LimitToCheck>
  constructLimitsToCheck(const std::string& limiterName,
                         const std::vector<Envoy::RateLimit::Descriptor>& request);

protected:
  DescriptorLimitRef getLimit(const std::string& limiterName,
                              const Envoy::RateLimit::Descriptor& descriptorInstance) const;

  void loadDescriptors(rateLimitDescriptorNode& parent,
                       const std::string& limitName,
                       const std::string& parentKey,
                       const google::protobuf::RepeatedPtrField<filter_protos::CongestionLimitDescriptor>& descriptors);

private:
  /**
   * @brief Dictionary which stores descriptor match trees by name.
   * Named `domains` in
   * https://github.com/envoyproxy/ratelimit/blob/c97749c/src/config/config_impl.go#L53
   */
  std::map<std::string, rateLimitDescriptorNode> limiters_{};
  Envoy::Api::Api& api_;
};

typedef std::shared_ptr<CongestionLimitEngine> CongestionLimitEngineSharedPtr;

} // namespace Engine
} // namespace CongestionLimiter
} // namespace Http
} // namespace Envoy
