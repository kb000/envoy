#include "congestionlimiter/congestionlimitengine.h"
#include "congestionlimiter/responseengine.h"
#include "envoy/http/codes.h"

#include "test/mocks/http/mocks.h"
#include "test/mocks/server/factory_context.h"
#include "test/test_common/logging.h"
#include "common/common/fancy_logger.h"
#include "common/common/logger.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "common/stats/isolated_store_impl.h"

using testing::_;
using testing::Eq;
using testing::NiceMock;
using testing::NaggyMock;
using testing::StrictMock;
using testing::Return;
using testing::ReturnRef;
using namespace envoy::config::filter::http;
using Envoy::LogRecordingSink;
using Envoy::LogLevelSetter;

namespace Envoy {
namespace Http {
namespace CongestionLimiter {
namespace Engine {

typedef std::unique_ptr<CongestionLimitEngine> CongestionLimitEnginePtr;
typedef std::unique_ptr<ResponseEngine> ResponseEnginePtr;

class LocalCongestionLimitEngineUnitTest : public testing::Test {
public:
  LocalCongestionLimitEngineUnitTest () {
    ON_CALL(file_system_, fileReadToEnd(_)).WillByDefault(Return(file_content_));
    ON_CALL(api_, fileSystem()).WillByDefault(ReturnRef(file_system_));
    ON_CALL(context_, api()).WillByDefault(ReturnRef(api_));
    ON_CALL(context_, scope()).WillByDefault(ReturnRef(scope_));
    ON_CALL(decoder_callbacks_, connection()).WillByDefault(Return(&connection_));
    ON_CALL(decoder_callbacks_, streamInfo()).WillByDefault(ReturnRef(stream_info_));
    ON_CALL(encoder_callbacks_, streamInfo()).WillByDefault(ReturnRef(stream_info_));
    ON_CALL(stream_info_, setDynamicMetadata(_, _)).WillByDefault(
      Invoke([this](const std::string& name, const ProtobufWkt::Struct& value){
        (*stream_info_.metadata_.mutable_filter_metadata())[name].MergeFrom(value);
        }));
    ON_CALL(stream_info_, routeEntry()).WillByDefault(Return(&route_entry_));
    ON_CALL(route_entry_, clusterName()).WillByDefault(ReturnRef(test_cluster_name_));
  }

  CongestionLimitEnginePtr makeLimitEngine() {
    return std::make_unique<Engine::CongestionLimitEngine>(api_);
  }

  ResponseEnginePtr makeResponseEngine() {
    return std::make_unique<Engine::ResponseEngine>(config_proto_.response_policies(0), context_);
  }

  localcongestionlimiter_filter::v3::LocalCongestionLimiter config_proto_;

protected:
  // Simple request headers
  Http::TestRequestHeaderMapImpl request_headers_{
      {":authority", "unittest.tess.io"}, {":path", "/testpath"}, {":method", "GET"}};
  // Sample response headers
  Http::TestResponseHeaderMapImpl response_headers_{
      {":status", "200"}};
  // Whether this is a header only request/response. CongestionLimiterFilter doesn't care.
  bool end_stream_ = false;

  std::string test_cluster_name_ = "testcluster-web-1-80/80/7067dc789f";
  std::string file_content_ = "file content";

  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks_;
  NiceMock<Http::MockStreamEncoderFilterCallbacks> encoder_callbacks_;
  NiceMock<Server::Configuration::MockFactoryContext> context_;
  StrictMock<Network::MockConnection> connection_;
  NiceMock<StreamInfo::MockStreamInfo> stream_info_;
  NiceMock<Router::MockRouteEntry> route_entry_;
  NiceMock<Stats::MockIsolatedStatsStore> scope_;
  NiceMock<Api::MockApi> api_;
  NiceMock<Filesystem::MockInstance> file_system_;
};

namespace {
const std::string config_base_yaml = R"EOF(
filter_enabled: true
congestion_limits:
- name: test-limit
  descriptor_components:
    - header_value_match:
        # descriptor_key: path_match # TODO[UFES-8084]: Use after 1.24.
        descriptor_value: testpath-trigger
        headers:
          - name: ":path"
            contains_match: "testpath"
    - destination_cluster: {{}}
  descriptors:
    - key: header_match
    # key: path_match # TODO[UFES-8084]: Use after 1.24.
      value: testpath-trigger
      descriptors: {}
  response_policy: test_response_policy
response_policies:
  - name: test_response_policy
    responses:
      - match:
          header:
            name: ":path"
            prefix_match: /testpath
#           string_match:  # TODO[UFES-8084]: Use after 1.24.
#             prefix: /testpath
#             ignore_case: true
        action: {}
)EOF";

const std::string config_descriptor2_test_cluster_yaml = "\n" R"EOF(
        - key: destination_cluster
          value: "testcluster-web-1-80/80/7067dc789f"
          limit: 
            fixed: { limit: 999 }
)EOF";

const std::string config_descriptor2_block_cluster_yaml = "\n" R"EOF(
        - key: destination_cluster
          value: "block-cluster"
          limit: 
            fixed: { limit: 0 }
)EOF";

const std::string config_descriptor2_shadow_cluster_yaml = "\n" R"EOF(
        - key: destination_cluster
          value: "shadow-cluster"
          limit: 
            fixed: { limit: 1 }
          shadow_mode: true
)EOF";

const std::string config_descriptor2_any_cluster_yaml = "\n" R"EOF(
        - key: destination_cluster
          # value: No value specified - match any!
          limit: 
            fixed: { limit: 10 }
)EOF";


const std::string config_static_response_bytes_yaml = "\n" R"EOF(
          static_response:
            response_code: 429
            source:
              inline_bytes: "H4sIAKqafmMAA3PLLy1SyCjNSylKTVEoKU/NK6nUzcvMS+UCAHYq0qsZAAAA"
)EOF";

const std::string static_response_body = "Four hundred twenty-nine\n";
}

TEST_F(LocalCongestionLimitEngineUnitTest, DescriptorMatchesNamedLimit) {
  std::string config_yaml = fmt::format(config_base_yaml, config_descriptor2_test_cluster_yaml, config_static_response_bytes_yaml);
  TestUtility::loadFromYamlAndValidate(config_yaml, config_proto_);
  ASSERT_EQ(1UL, config_proto_.congestion_limits().size());
  CongestionLimitEnginePtr engine = makeLimitEngine();
  engine->loadConfig(config_proto_.congestion_limits(0));

  RequestDescription request {
    Envoy::RateLimit::Descriptor {{
        Envoy::RateLimit::DescriptorEntry{"header_match", "testpath-trigger"},
        Envoy::RateLimit::DescriptorEntry{"destination_cluster", "testcluster-web-1-80/80/7067dc789f"}
    }}
  };

  auto limits = engine->constructLimitsToCheck("test-limit", request);

  ASSERT_EQ(1, limits.size());
  ASSERT_NE(nullptr, limits[0].rateLimit.lock());
  EXPECT_EQ("test-limit", limits[0].rateLimit.lock()->FullKey.substr(0,strlen("test-limit")));
};

TEST_F(LocalCongestionLimitEngineUnitTest, ResponseMatchesAction) {
  std::string config_yaml = fmt::format(config_base_yaml, config_descriptor2_test_cluster_yaml, config_static_response_bytes_yaml);
  TestUtility::loadFromYamlAndValidate(config_yaml, config_proto_);
  ASSERT_EQ(1UL, config_proto_.congestion_limits().size());
  ResponseEnginePtr engine = makeResponseEngine();
  
  CBMatcher::Context requestContext(*decoder_callbacks_.connection(), request_headers_);
  auto rule = engine->getMatchingRule(requestContext);

  ASSERT_TRUE(rule.has_value());
  ASSERT_EQ(rule->action().static_response().response_code(), 429);

  auto action = engine->getAction(rule.value());
  ASSERT_EQ(action->getActionName(), "static_response");
  auto status = action->execute(*decoder_callbacks_.connection(), request_headers_, &decoder_callbacks_);
  ASSERT_EQ(status, Http::FilterHeadersStatus::StopIteration);
};

TEST_F(LocalCongestionLimitEngineUnitTest, ResponseNoMatchingAction) {
  std::string config_yaml = fmt::format(config_base_yaml, config_descriptor2_test_cluster_yaml, config_static_response_bytes_yaml);
  TestUtility::loadFromYamlAndValidate(config_yaml, config_proto_);
  ASSERT_EQ(1UL, config_proto_.congestion_limits().size());
  ResponseEnginePtr engine = makeResponseEngine();
  
  request_headers_.setPath("/ResponseNoMatchingAction");
  CBMatcher::Context requestContext(*decoder_callbacks_.connection(), request_headers_);
  auto rule = engine->getMatchingRule(requestContext);

  ASSERT_FALSE(rule.has_value());
};


} // namespace Engine
} // namespace CongestionLimiter
} // namespace Http
} // namespace Envoy
