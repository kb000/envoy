#pragma once

#include "envoy/config/filter/http/localcongestionlimiter_filter/v3/localcongestionlimiter_filter.pb.h"
#include "envoy/config/filter/http/localcongestionlimiter_filter/v3/localcongestionlimiter_filter.pb.validate.h"

#include "envoy/http/filter.h"
#include "envoy/server/filter_config.h"

#include "extensions/filters/http/common/factory_base.h"
#include "extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Http {
namespace CongestionLimiter {

/**
 * Config registration for the filter. @see NamedHttpFilterConfigFactory.
 */
class LocalCongestionLimiterConfigFactory
    : public Extensions::HttpFilters::Common::FactoryBase<envoy::config::filter::http::localcongestionlimiter_filter::v3::LocalCongestionLimiter> {
public:
  LocalCongestionLimiterConfigFactory() : FactoryBase("envoy.localcongestionlimiter") {}

  Http::FilterFactoryCb
  createFilterFactoryFromProtoTyped(const envoy::config::filter::http::localcongestionlimiter_filter::v3::LocalCongestionLimiter& proto_config,
                                    const std::string& stats_prefix,
                                    Server::Configuration::FactoryContext& context) override;

private:
  Http::FilterFactoryCb
  createFilter(const envoy::config::filter::http::localcongestionlimiter_filter::v3::LocalCongestionLimiter& proto_config,
               const std::string& stats_prefix, Server::Configuration::FactoryContext& context);

};

} // namespace CongestionLimiter
} // namespace Http
} // namespace Envoy
