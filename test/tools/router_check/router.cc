#include "test/tools/router_check/router.h"

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/route/v3/route.pb.h"
#include "envoy/type/v3/percent.pb.h"

#include "common/network/utility.h"
#include "common/protobuf/message_validator_impl.h"
#include "common/protobuf/utility.h"
#include "common/runtime/runtime_impl.h"
#include "common/stream_info/stream_info_impl.h"

#include "test/test_common/printers.h"

namespace {
  const std::string to_string(envoy::config::route::v3::HeaderMatcher::HeaderMatchSpecifierCase kCase) {
    switch(kCase) {
      case envoy::config::route::v3::HeaderMatcher::HeaderMatchSpecifierCase::kExactMatch:
        return "kExactMatch"; break;
      case envoy::config::route::v3::HeaderMatcher::HeaderMatchSpecifierCase::kHiddenEnvoyDeprecatedRegexMatch:
        return "kHiddenEnvoyDeprecatedRegexMatch"; break;
      case envoy::config::route::v3::HeaderMatcher::HeaderMatchSpecifierCase::kSafeRegexMatch:
        return "kSafeRegexMatch"; break;
      case envoy::config::route::v3::HeaderMatcher::HeaderMatchSpecifierCase::kRangeMatch:
        return "kRangeMatch"; break;
      case envoy::config::route::v3::HeaderMatcher::HeaderMatchSpecifierCase::kPresentMatch:
        return "kPresentMatch"; break;
      case envoy::config::route::v3::HeaderMatcher::HeaderMatchSpecifierCase::kPrefixMatch:
        return "kPrefixMatch"; break;
      case envoy::config::route::v3::HeaderMatcher::HeaderMatchSpecifierCase::kSuffixMatch:
        return "kSuffixMatch"; break;
      default:
        return "HEADER_MATCH_SPECIFIER_NOT_SET"; break;
    }
  }
}

namespace Envoy {
// static
ToolConfig ToolConfig::create(const envoy::RouterCheckToolSchema::ValidationItem& check_config) {
  // Add header field values
  std::unique_ptr<Http::TestRequestHeaderMapImpl> request_headers(
      new Http::TestRequestHeaderMapImpl());
  std::unique_ptr<Http::TestResponseHeaderMapImpl> response_headers(
      new Http::TestResponseHeaderMapImpl());
  request_headers->addCopy(":authority", check_config.input().authority());
  request_headers->addCopy(":path", check_config.input().path());
  request_headers->addCopy(":method", check_config.input().method());
  request_headers->addCopy("x-forwarded-proto", check_config.input().ssl() ? "https" : "http");

  if (check_config.input().internal()) {
    request_headers->addCopy("x-envoy-internal", "true");
  }

  if (check_config.input().additional_request_headers().data()) {
    for (const envoy::config::core::v3::HeaderValue& header_config :
         check_config.input().additional_request_headers()) {
      request_headers->addCopy(header_config.key(), header_config.value());
    }
  }

  if (check_config.input().additional_response_headers().data()) {
    for (const envoy::config::core::v3::HeaderValue& header_config :
         check_config.input().additional_response_headers()) {
      response_headers->addCopy(header_config.key(), header_config.value());
    }
  }

  return ToolConfig(std::move(request_headers), std::move(response_headers),
                    check_config.input().random_value());
}

ToolConfig::ToolConfig(std::unique_ptr<Http::TestRequestHeaderMapImpl> request_headers,
                       std::unique_ptr<Http::TestResponseHeaderMapImpl> response_headers,
                       int random_value)
    : request_headers_(std::move(request_headers)), response_headers_(std::move(response_headers)),
      random_value_(random_value) {}

// static
RouterCheckTool RouterCheckTool::create(const std::string& router_config_file,
                                        const bool disable_deprecation_check) {
  // TODO(hennna): Allow users to load a full config and extract the route configuration from it.
  envoy::config::route::v3::RouteConfiguration route_config;
  auto stats = std::make_unique<Stats::IsolatedStoreImpl>();
  auto api = Api::createApiForTest(*stats);
  TestUtility::loadFromFile(router_config_file, route_config, *api);
  assignUniqueRouteNames(route_config);
  assignRuntimeFraction(route_config);
  auto factory_context =
      std::make_unique<NiceMock<Server::Configuration::MockServerFactoryContext>>();
  auto config = std::make_unique<Router::ConfigImpl>(
      route_config, *factory_context, ProtobufMessage::getNullValidationVisitor(), false);
  if (!disable_deprecation_check) {
    MessageUtil::checkForUnexpectedFields(route_config,
                                          ProtobufMessage::getStrictValidationVisitor(),
                                          &factory_context->runtime_loader_);
  }

  return RouterCheckTool(std::move(factory_context), std::move(config), std::move(stats),
                         std::move(api), Coverage(route_config));
}

void RouterCheckTool::assignUniqueRouteNames(
    envoy::config::route::v3::RouteConfiguration& route_config) {
  Runtime::RandomGeneratorImpl random;
  for (auto& host : *route_config.mutable_virtual_hosts()) {
    for (auto& route : *host.mutable_routes()) {
      route.set_name(random.uuid());
    }
  }
}

void RouterCheckTool::assignRuntimeFraction(
    envoy::config::route::v3::RouteConfiguration& route_config) {
  for (auto& host : *route_config.mutable_virtual_hosts()) {
    for (auto& route : *host.mutable_routes()) {
      if (route.match().has_runtime_fraction() &&
          route.match().runtime_fraction().default_value().numerator() == 0) {
        route.mutable_match()->mutable_runtime_fraction()->mutable_default_value()->set_numerator(
            1);
      }
    }
  }
}

void RouterCheckTool::finalizeHeaders(ToolConfig& tool_config,
                                      Envoy::StreamInfo::StreamInfoImpl stream_info) {
  if (!headers_finalized_ && tool_config.route_ != nullptr) {
    if (tool_config.route_->directResponseEntry() != nullptr) {
      tool_config.route_->directResponseEntry()->rewritePathHeader(*tool_config.request_headers_,
                                                                   true);
      sendLocalReply(tool_config, *tool_config.route_->directResponseEntry());
      tool_config.route_->directResponseEntry()->finalizeResponseHeaders(
          *tool_config.response_headers_, stream_info);
    } else if (tool_config.route_->routeEntry() != nullptr) {
      tool_config.route_->routeEntry()->finalizeRequestHeaders(*tool_config.request_headers_,
                                                               stream_info, true);
      tool_config.route_->routeEntry()->finalizeResponseHeaders(*tool_config.response_headers_,
                                                                stream_info);
    }
  }

  headers_finalized_ = true;
}

void RouterCheckTool::sendLocalReply(ToolConfig& tool_config,
                                     const Router::DirectResponseEntry& entry) {
  const auto& encode_headers = [&](Http::ResponseHeaderMapPtr&& headers, bool end_stream) -> void {
    UNREFERENCED_PARAMETER(end_stream);
    Http::HeaderMapImpl::copyFrom(tool_config.response_headers_->header_map_, *headers);
  };

  const auto& encode_data = [&](Buffer::Instance& data, bool end_stream) -> void {
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(end_stream);
  };

  Envoy::Http::Utility::sendLocalReply(false, encode_headers, encode_data, false,
                                       entry.responseCode(), entry.responseBody(), absl::nullopt,
                                       false);
}

RouterCheckTool::RouterCheckTool(
    std::unique_ptr<NiceMock<Server::Configuration::MockServerFactoryContext>> factory_context,
    std::unique_ptr<Router::ConfigImpl> config, std::unique_ptr<Stats::IsolatedStoreImpl> stats,
    Api::ApiPtr api, Coverage coverage)
    : factory_context_(std::move(factory_context)), config_(std::move(config)),
      stats_(std::move(stats)), api_(std::move(api)), coverage_(std::move(coverage)) {
  ON_CALL(factory_context_->runtime_loader_.snapshot_,
          featureEnabled(_, testing::An<const envoy::type::v3::FractionalPercent&>(),
                         testing::An<uint64_t>()))
      .WillByDefault(testing::Invoke(this, &RouterCheckTool::runtimeMock));
}

Json::ObjectSharedPtr loadFromFile(const std::string& file_path, Api::Api& api) {
  std::string contents = api.fileSystem().fileReadToEnd(file_path);
  if (absl::EndsWith(file_path, ".yaml")) {
    contents = MessageUtil::getJsonStringFromMessage(ValueUtil::loadFromYaml(contents));
  }
  return Json::Factory::loadFromString(contents);
}

bool RouterCheckTool::compareEntries(const std::string& expected_routes) {
  envoy::RouterCheckToolSchema::Validation validation_config;
  auto stats = std::make_unique<Stats::IsolatedStoreImpl>();
  auto api = Api::createApiForTest(*stats);
  const std::string contents = api->fileSystem().fileReadToEnd(expected_routes);
  TestUtility::loadFromFile(expected_routes, validation_config, *api);
  TestUtility::validate(validation_config);

  bool no_failures = true;
  for (const envoy::RouterCheckToolSchema::ValidationItem& check_config :
       validation_config.tests()) {
    active_runtime_ = check_config.input().runtime();
    headers_finalized_ = false;
    Envoy::StreamInfo::StreamInfoImpl stream_info(Envoy::Http::Protocol::Http11,
                                                  factory_context_->dispatcher().timeSource());
    stream_info.setDownstreamRemoteAddress(Network::Utility::getCanonicalIpv4LoopbackAddress());
    ToolConfig tool_config = ToolConfig::create(check_config);
    tool_config.route_ =
        config_->route(*tool_config.request_headers_, stream_info, tool_config.random_value_);

    const std::string& test_name = check_config.test_name();
    tests_.emplace_back(test_name, std::vector<std::string>{});
    const envoy::RouterCheckToolSchema::ValidationAssert& validate = check_config.validate();

    using CheckerFunc =
        std::function<bool(ToolConfig&, const envoy::RouterCheckToolSchema::ValidationAssert&)>;
    CheckerFunc checkers[] = {
        [this](auto&... params) -> bool { return this->compareCluster(params...); },
        [this](auto&... params) -> bool { return this->compareVirtualCluster(params...); },
        [this](auto&... params) -> bool { return this->compareVirtualHost(params...); },
        [this](auto&... params) -> bool { return this->compareRewritePath(params...); },
        [this](auto&... params) -> bool { return this->compareRewriteHost(params...); },
        [this](auto&... params) -> bool { return this->compareRedirectPath(params...); },
        [this](auto&... params) -> bool { return this->compareRequestHeaderFields(params...); },
        [this](auto&... params) -> bool { return this->compareResponseHeaderFields(params...); },
    };
    finalizeHeaders(tool_config, stream_info);
    // Call appropriate function for each match case.
    for (const auto& test : checkers) {
      if (!test(tool_config, validate)) {
        no_failures = false;
      }
    }
  }
  printResults();
  return no_failures;
}

bool RouterCheckTool::compareCluster(ToolConfig& tool_config, const std::string& expected) {
  std::string actual = "";

  if (tool_config.route_->routeEntry() != nullptr) {
    actual = tool_config.route_->routeEntry()->clusterName();
  }
  const bool matches = compareResults(actual, expected, "cluster_name");
  if (matches && tool_config.route_->routeEntry() != nullptr) {
    coverage_.markClusterCovered(*tool_config.route_);
  }
  return matches;
}

bool RouterCheckTool::compareCluster(
    ToolConfig& tool_config, const envoy::RouterCheckToolSchema::ValidationAssert& expected) {
  if (!expected.has_cluster_name()) {
    return true;
  }
  if (tool_config.route_ == nullptr) {
    return compareResults("", expected.cluster_name().value(), "cluster_name");
  }
  return compareCluster(tool_config, expected.cluster_name().value());
}

bool RouterCheckTool::compareVirtualCluster(ToolConfig& tool_config, const std::string& expected) {
  std::string actual = "";

  if (tool_config.route_->routeEntry() != nullptr &&
      tool_config.route_->routeEntry()->virtualCluster(*tool_config.request_headers_) != nullptr) {
    Stats::StatName stat_name =
        tool_config.route_->routeEntry()->virtualCluster(*tool_config.request_headers_)->statName();
    actual = tool_config.symbolTable().toString(stat_name);
  }
  const bool matches = compareResults(actual, expected, "virtual_cluster_name");
  if (matches && tool_config.route_->routeEntry() != nullptr) {
    coverage_.markVirtualClusterCovered(*tool_config.route_);
  }
  return matches;
}

bool RouterCheckTool::compareVirtualCluster(
    ToolConfig& tool_config, const envoy::RouterCheckToolSchema::ValidationAssert& expected) {
  if (!expected.has_virtual_cluster_name()) {
    return true;
  }
  if (tool_config.route_ == nullptr) {
    return compareResults("", expected.virtual_cluster_name().value(), "virtual_cluster_name");
  }
  return compareVirtualCluster(tool_config, expected.virtual_cluster_name().value());
}

bool RouterCheckTool::compareVirtualHost(ToolConfig& tool_config, const std::string& expected) {
  std::string actual = "";
  if (tool_config.route_->routeEntry() != nullptr) {
    Stats::StatName stat_name = tool_config.route_->routeEntry()->virtualHost().statName();
    actual = tool_config.symbolTable().toString(stat_name);
  }
  const bool matches = compareResults(actual, expected, "virtual_host_name");
  if (matches && tool_config.route_->routeEntry() != nullptr) {
    coverage_.markVirtualHostCovered(*tool_config.route_);
  }
  return matches;
}

bool RouterCheckTool::compareVirtualHost(
    ToolConfig& tool_config, const envoy::RouterCheckToolSchema::ValidationAssert& expected) {
  if (!expected.has_virtual_host_name()) {
    return true;
  }
  if (tool_config.route_ == nullptr) {
    return compareResults("", expected.virtual_host_name().value(), "virtual_host_name");
  }
  return compareVirtualHost(tool_config, expected.virtual_host_name().value());
}

bool RouterCheckTool::compareRewritePath(ToolConfig& tool_config, const std::string& expected) {
  std::string actual = "";
  if (tool_config.route_->routeEntry() != nullptr) {
    actual = tool_config.request_headers_->get_(Http::Headers::get().Path);
  }
  const bool matches = compareResults(actual, expected, "path_rewrite");
  if (matches && tool_config.route_->routeEntry() != nullptr) {
    coverage_.markPathRewriteCovered(*tool_config.route_);
  }
  return matches;
}

bool RouterCheckTool::compareRewritePath(
    ToolConfig& tool_config, const envoy::RouterCheckToolSchema::ValidationAssert& expected) {
  if (!expected.has_path_rewrite()) {
    return true;
  }
  if (tool_config.route_ == nullptr) {
    return compareResults("", expected.path_rewrite().value(), "path_rewrite");
  }
  return compareRewritePath(tool_config, expected.path_rewrite().value());
}

bool RouterCheckTool::compareRewriteHost(ToolConfig& tool_config, const std::string& expected) {
  std::string actual = "";
  if (tool_config.route_->routeEntry() != nullptr) {
    actual = tool_config.request_headers_->get_(Http::Headers::get().Host);
  }
  const bool matches = compareResults(actual, expected, "host_rewrite");
  if (matches && tool_config.route_->routeEntry() != nullptr) {
    coverage_.markHostRewriteCovered(*tool_config.route_);
  }
  return matches;
}

bool RouterCheckTool::compareRewriteHost(
    ToolConfig& tool_config, const envoy::RouterCheckToolSchema::ValidationAssert& expected) {
  if (!expected.has_host_rewrite()) {
    return true;
  }
  if (tool_config.route_ == nullptr) {
    return compareResults("", expected.host_rewrite().value(), "host_rewrite");
  }
  return compareRewriteHost(tool_config, expected.host_rewrite().value());
}

bool RouterCheckTool::compareRedirectPath(ToolConfig& tool_config, const std::string& expected) {
  std::string actual = "";
  if (tool_config.route_->directResponseEntry() != nullptr) {
    actual = tool_config.route_->directResponseEntry()->newPath(*tool_config.request_headers_);
  }

  const bool matches = compareResults(actual, expected, "path_redirect");
  if (matches && tool_config.route_->directResponseEntry() != nullptr) {
    coverage_.markRedirectPathCovered(*tool_config.route_);
  }
  return matches;
}

bool RouterCheckTool::compareRedirectPath(
    ToolConfig& tool_config, const envoy::RouterCheckToolSchema::ValidationAssert& expected) {
  if (!expected.has_path_redirect()) {
    return true;
  }
  if (tool_config.route_ == nullptr) {
    return compareResults("", expected.path_redirect().value(), "path_redirect");
  }
  return compareRedirectPath(tool_config, expected.path_redirect().value());
}

bool RouterCheckTool::compareRequestHeaderFields(
    ToolConfig& tool_config, const envoy::RouterCheckToolSchema::ValidationAssert& expected) {
  bool no_failures = true;
  if (expected.request_header_matches().data()) {
    for (const envoy::config::route::v3::HeaderMatcher& header : expected.request_header_matches()) {
      switch (header.header_match_specifier_case()) {
        case envoy::config::route::v3::HeaderMatcher::HeaderMatchSpecifierCase::kExactMatch:
          if (!compareHeaderField(*tool_config.request_headers_, header.name(), header.exact_match(), "request_header_fields", !header.invert_match())) {
            no_failures = false;
          }
          break;
        case envoy::config::route::v3::HeaderMatcher::HeaderMatchSpecifierCase::kPresentMatch:
          if (!expectHeaderField(*tool_config.request_headers_, header.name(), "request_header_fields", !header.invert_match())) {
            no_failures = false;
          }
          break;
        default:
          // Not implemented!
          tests_.back().second.emplace_back("HeaderMatcher option " + ::to_string(header.header_match_specifier_case()) + " not supported.");
          no_failures = false;
          break;
      }
    }
  }
  return no_failures;
}

bool RouterCheckTool::compareResponseHeaderFields(
    ToolConfig& tool_config, const envoy::RouterCheckToolSchema::ValidationAssert& expected) {
  bool no_failures = true;
  if (expected.response_header_matches().data()) {
    for (const envoy::config::route::v3::HeaderMatcher& header : expected.response_header_matches()) {
      switch (header.header_match_specifier_case()) {
        case envoy::config::route::v3::HeaderMatcher::HeaderMatchSpecifierCase::kExactMatch:
          if (!compareHeaderField(*tool_config.response_headers_, header.name(), header.exact_match(), "response_header_fields", !header.invert_match())) {
            no_failures = false;
          }
          break;
        case envoy::config::route::v3::HeaderMatcher::HeaderMatchSpecifierCase::kPresentMatch:
          if (!expectHeaderField(*tool_config.response_headers_, header.name(), "response_header_fields", !header.invert_match())) {
            no_failures = false;
          }
          break;
        default:
          // Not implemented!
          tests_.back().second.emplace_back("HeaderMatcher option " + ::to_string(header.header_match_specifier_case()) + " not supported.");
          no_failures = false;
          break;
      }
    }
  }
  return no_failures;
}

template<typename HM>
bool RouterCheckTool::compareHeaderField(const HM& header_map, const std::string& field,
                                                 const std::string& expected, const std::string& test_type, const bool expect_match) {
  std::string actual = header_map.get_(field);
  return compareResults(actual, expected, test_type, expect_match);
}

template<typename HM>
bool RouterCheckTool::expectHeaderField(const HM& header_map, const std::string& field, const std::string& test_type, const bool expect_present) {
  if (header_map.has(field) != expect_present) {
    tests_.back().second.emplace_back("expected: [has(" + field + "):" + std::string{expect_present} + "], " + 
                           "actual: [has(" + field + "):" + std::string{!expect_present} + "], test type:" + test_type);
    return false;
  }
  return true;
}

bool RouterCheckTool::compareResults(const std::string& actual, const std::string& expected, const std::string& test_type, const bool expect_match) {
  if ((expected == actual) != expect_match) {
    tests_.back().second.emplace_back("expected: [" + expected + "], actual: " +( expect_match ? "" : "NOT " ) + "[" + actual + "], " +
                                      "test type: " + test_type);
    return false;
  }
  return true;
}

void RouterCheckTool::printResults() {
  // Output failure details to stdout if details_ flag is set to true
  for (const auto& test_result : tests_) {
    // All test names are printed if the details_ flag is true unless only_show_failures_ is also
    // true.
    if ((details_ && !only_show_failures_) ||
        (only_show_failures_ && !test_result.second.empty())) {
      std::cout << test_result.first << std::endl;
      for (const auto& failure : test_result.second) {
        std::cerr << failure << std::endl;
      }
    }
  }
}

// The Mock for runtime value checks.
// This is a simple implementation to mimic the actual runtime checks in Snapshot.featureEnabled
bool RouterCheckTool::runtimeMock(absl::string_view key,
                                  const envoy::type::v3::FractionalPercent& default_value,
                                  uint64_t random_value) {
  return !active_runtime_.empty() && key.compare(active_runtime_) == 0 &&
         ProtobufPercentHelper::evaluateFractionalPercent(default_value, random_value);
}

Options::Options(int argc, char** argv) {
  TCLAP::CmdLine cmd("router_check_tool", ' ', "none", true);
  TCLAP::SwitchArg is_detailed("d", "details", "Show detailed test execution results", cmd, false);
  TCLAP::SwitchArg only_show_failures("", "only-show-failures", "Only display failing tests", cmd,
                                      false);
  TCLAP::SwitchArg disable_deprecation_check("", "disable-deprecation-check",
                                             "Disable deprecated fields check", cmd, false);
  TCLAP::ValueArg<double> fail_under("f", "fail-under",
                                     "Fail if test coverage is under a specified amount", false,
                                     0.0, "float", cmd);
  TCLAP::SwitchArg comprehensive_coverage(
      "", "covall", "Measure coverage by checking all route fields", cmd, false);
  TCLAP::ValueArg<std::string> config_path("c", "config-path", "Path to configuration file.", false,
                                           "", "string", cmd);
  TCLAP::ValueArg<std::string> test_path("t", "test-path", "Path to test file.", false, "",
                                         "string", cmd);
  TCLAP::UnlabeledMultiArg<std::string> unlabelled_configs(
      "unlabelled-configs", "unlabelled configs", false, "unlabelledConfigStrings", cmd);
  try {
    cmd.parse(argc, argv);
  } catch (TCLAP::ArgException& e) {
    std::cerr << "error: " << e.error() << std::endl;
    exit(EXIT_FAILURE);
  }

  is_detailed_ = is_detailed.getValue();
  only_show_failures_ = only_show_failures.getValue();
  fail_under_ = fail_under.getValue();
  comprehensive_coverage_ = comprehensive_coverage.getValue();
  disable_deprecation_check_ = disable_deprecation_check.getValue();

  config_path_ = config_path.getValue();
  test_path_ = test_path.getValue();
  if (config_path_.empty() || test_path_.empty()) {
    std::cerr << "error: "
              << "Both --config-path/c and --test-path/t are mandatory" << std::endl;
    exit(EXIT_FAILURE);
  }
}
} // namespace Envoy
