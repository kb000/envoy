#include "congestionlimiter/localcongestionlimiter_filter.h"

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
using testing::StrEq;
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

typedef std::unique_ptr<LocalCongestionLimiter> LocalCongestionLimiterPtr;

class LocalCongestionLimiterUnitTest : public testing::Test {
public:
  LocalCongestionLimiterUnitTest () {
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
    limit_to_check_.rateLimit = Engine::DescriptorLimitRef{};
  }

  LocalCongestionLimiterPtr makeFilter(const localcongestionlimiter_filter::v3::LocalCongestionLimiter& config_proto, std::string stats_prefix) {
    auto limit_proto = config_proto.congestion_limits(0);
    config_ = std::make_shared<CongestionLimiter::LocalCongestionLimiterConfig>(
        limit_proto, config_proto, stats_prefix, context_.scope(), context_);
    auto filter = std::make_unique<CongestionLimiter::LocalCongestionLimiter>(config_);
    filter->setDecoderFilterCallbacks(decoder_callbacks_);
    filter->setEncoderFilterCallbacks(encoder_callbacks_);
    return filter;
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
  NiceMock<Network::MockConnection> connection_;
  NiceMock<StreamInfo::MockStreamInfo> stream_info_;
  NiceMock<Router::MockRouteEntry> route_entry_;
  NiceMock<Stats::MockIsolatedStatsStore> scope_;
  NiceMock<Api::MockApi> api_;
  NiceMock<Filesystem::MockInstance> file_system_;

  Engine::LimitToCheck limit_to_check_;
  CongestionLimiter::LocalCongestionLimiterConfigSharedPtr config_;
};

namespace {
const std::string config_base_yaml = R"EOF(
filter_enabled: true
congestion_limits:
- name: test_limit
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

const std::string config_monitor_yaml = "\n" R"EOF(
          monitor: true
)EOF";

const std::string config_static_response_bytes_yaml = "\n" R"EOF(
          static_response:
            response_code: 429
            source:
              inline_bytes: "H4sIAKqafmMAA3PLLy1SyCjNSylKTVEoKU/NK6nUzcvMS+UCAHYq0qsZAAAA"
)EOF";

const std::string static_response_body = "Four hundred twenty-nine\n";
}


TEST_F(LocalCongestionLimiterUnitTest, PolicyNoDescriptorNoMatchNoAction) {
  std::string config_yaml = fmt::format(config_base_yaml, config_descriptor2_test_cluster_yaml, config_static_response_bytes_yaml);
  TestUtility::loadFromYamlAndValidate(config_yaml, config_proto_);
  ASSERT_EQ(1UL, config_proto_.congestion_limits().size());
  LocalCongestionLimiterPtr filter = makeFilter(config_proto_, "test.counters");

  // Set a path that won't generate descriptors.
  request_headers_.setPath("/no-match-path");

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter->decodeHeaders(request_headers_, end_stream_));
  EXPECT_EQ(0UL, scope_.counter("test.counters.localcongestionlimiter_descriptor_entry_count").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.localcongestionlimiter_generated_empty_descriptors").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.limit_hit").value());
  EXPECT_EQ(0, stream_info_.metadata_.filter_metadata().size());

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter->encodeHeaders(response_headers_, end_stream_));
  EXPECT_EQ(0, stream_info_.metadata_.filter_metadata().size());
};

TEST_F(LocalCongestionLimiterUnitTest, PolicyDescriptorNoMatchNoAction) {
  std::string config_yaml = fmt::format(config_base_yaml, config_descriptor2_test_cluster_yaml, config_static_response_bytes_yaml);
  TestUtility::loadFromYamlAndValidate(config_yaml, config_proto_);
  ASSERT_EQ(1UL, config_proto_.congestion_limits().size());
  LocalCongestionLimiterPtr filter = makeFilter(config_proto_, "test.counters");

  // Set a path that will generate descriptors.
  request_headers_.setPath("/testpath");
  // Set an upstream cluster that will not match the descriptor tree.
  std::string other_cluster{"other-cluster"};
  EXPECT_CALL(route_entry_, clusterName()).WillRepeatedly(ReturnRef(other_cluster));

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter->decodeHeaders(request_headers_, end_stream_));
  EXPECT_EQ(2UL, scope_.counter("test.counters.localcongestionlimiter_descriptor_entry_count").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.localcongestionlimiter_generated_empty_descriptors").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_limit.described").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.limit_hit").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.localcongestionlimiter_descriptors_hit_no_limits").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_limit.under_limit").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_limit.over_limit").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_response_policy").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_response_policy.static_response").value());
  EXPECT_EQ(0, stream_info_.metadata_.filter_metadata().size());

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter->encodeHeaders(response_headers_, end_stream_));
  EXPECT_EQ(0, stream_info_.metadata_.filter_metadata().size());
};

TEST_F(LocalCongestionLimiterUnitTest, PolicyDescriptorMatchNoAction) {
  std::string config_yaml = fmt::format(config_base_yaml, config_descriptor2_test_cluster_yaml, config_static_response_bytes_yaml);
  TestUtility::loadFromYamlAndValidate(config_yaml, config_proto_);
  ASSERT_EQ(1UL, config_proto_.congestion_limits().size());
  LocalCongestionLimiterPtr filter = makeFilter(config_proto_, "test.counters");

  // Set a path that will generate descriptors.
  request_headers_.setPath("/testpath");
  // The default upstream cluster will match the descriptor tree.

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter->decodeHeaders(request_headers_, end_stream_));
  EXPECT_EQ(2UL, scope_.counter("test.counters.localcongestionlimiter_descriptor_entry_count").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.localcongestionlimiter_generated_empty_descriptors").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_limit.described").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.limit_hit").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.localcongestionlimiter_descriptors_hit_no_limits").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_limit.under_limit").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_limit.over_limit").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_response_policy").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.localcongestionlimiter_response_policy_no_connection").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_response_policy.no_match").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_response_policy.static_response").value());
  EXPECT_EQ(0, stream_info_.metadata_.filter_metadata().size());

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter->encodeHeaders(response_headers_, end_stream_));
  EXPECT_EQ(0, stream_info_.metadata_.filter_metadata().size());
};

TEST_F(LocalCongestionLimiterUnitTest, PolicyDescriptorMatchMonitorAction) {
  std::string config_yaml = fmt::format(config_base_yaml, config_descriptor2_block_cluster_yaml, config_monitor_yaml);
  TestUtility::loadFromYamlAndValidate(config_yaml, config_proto_);
  ASSERT_EQ(1UL, config_proto_.congestion_limits().size());
  LocalCongestionLimiterPtr filter = makeFilter(config_proto_, "test.counters");

  // Set a path that will generate descriptors.
  request_headers_.setPath("/testpath");
  // Set an upstream cluster that will match the 'block' descriptor tree.
  std::string block_cluster{"block-cluster"};
  EXPECT_CALL(route_entry_, clusterName()).WillRepeatedly(ReturnRef(block_cluster));

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter->decodeHeaders(request_headers_, end_stream_));
  EXPECT_EQ(2UL, scope_.counter("test.counters.localcongestionlimiter_descriptor_entry_count").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.localcongestionlimiter_generated_empty_descriptors").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_limit.described").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.limit_hit").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.localcongestionlimiter_descriptors_hit_no_limits").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_limit.under_limit").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_limit.over_limit").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_response_policy").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.localcongestionlimiter_response_policy_no_connection").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_response_policy.no_match").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_response_policy.monitor").value());
  EXPECT_EQ(0, stream_info_.metadata_.filter_metadata().size());

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter->encodeHeaders(response_headers_, end_stream_));
  EXPECT_EQ(0, stream_info_.metadata_.filter_metadata().size());
};

TEST_F(LocalCongestionLimiterUnitTest, PolicyDescriptorMatchBlockAction) {
  std::string config_yaml = fmt::format(config_base_yaml, config_descriptor2_block_cluster_yaml, config_static_response_bytes_yaml);
  TestUtility::loadFromYamlAndValidate(config_yaml, config_proto_);
  ASSERT_EQ(1UL, config_proto_.congestion_limits().size());
  LocalCongestionLimiterPtr filter = makeFilter(config_proto_, "test.counters");

  // Set a path that will generate descriptors.
  request_headers_.setPath("/testpath");
  // Set an upstream cluster that will match the 'block' descriptor tree.
  std::string block_cluster{"block-cluster"};
  EXPECT_CALL(route_entry_, clusterName()).WillRepeatedly(ReturnRef(block_cluster));

  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter->decodeHeaders(request_headers_, end_stream_));
  EXPECT_EQ(2UL, scope_.counter("test.counters.localcongestionlimiter_descriptor_entry_count").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.localcongestionlimiter_generated_empty_descriptors").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_limit.described").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.limit_hit").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.localcongestionlimiter_descriptors_hit_no_limits").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_limit.under_limit").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_limit.over_limit").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_response_policy").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.localcongestionlimiter_response_policy_no_connection").value());
  EXPECT_EQ(0UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_response_policy.no_match").value());
  EXPECT_EQ(1UL, scope_.counter("test.counters.edge_localcongestionlimiter.test_response_policy.static_response").value());
  EXPECT_EQ(0, stream_info_.metadata_.filter_metadata().size());

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter->encodeHeaders(response_headers_, end_stream_));
  EXPECT_EQ(0, stream_info_.metadata_.filter_metadata().size());
};

} // namespace CongestionLimiter
} // namespace Http
} // namespace Envoy
