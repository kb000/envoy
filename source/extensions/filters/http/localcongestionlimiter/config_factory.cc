#include "envoy/registry/registry.h"
#include "config_factory.h"
#include "localcongestionlimiter_filter.h"
#include "envoy/config/filter/http/localcongestionlimiter_filter/v3/localcongestionlimiter_filter.pb.h"
#include "envoy/config/filter/http/localcongestionlimiter_filter/v3/localcongestionlimiter_filter.pb.validate.h"

namespace Envoy {
namespace Http {
namespace CongestionLimiter {


namespace filter_protos = envoy::config::filter::http::localcongestionlimiter_filter::v3;

Http::FilterFactoryCb
LocalCongestionLimiterConfigFactory::createFilterFactoryFromProtoTyped(
                                  const filter_protos::LocalCongestionLimiter& proto_config,
                                  const std::string& stats_prefix,
                                  Server::Configuration::FactoryContext& context) {
  std::vector<LocalCongestionLimiterConfigSharedPtr> filter_configs{};
  for (auto congestion_limit : proto_config.congestion_limits()) {
    filter_configs.push_back(
      std::make_shared<LocalCongestionLimiterConfig>(
        congestion_limit, proto_config,
        stats_prefix, context.scope(), context));
  }

  return [filter_configs](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    for (auto filter_config : filter_configs) {
      callbacks.addStreamFilter(std::make_shared<LocalCongestionLimiter>(filter_config));
    }
  };
}

REGISTER_FACTORY(LocalCongestionLimiterConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace CongestionLimiter
} // namespace Http
} // namespace Envoy
