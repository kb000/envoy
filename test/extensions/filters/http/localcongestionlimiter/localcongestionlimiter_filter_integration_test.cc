#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include "test/common/concurrency_test_base.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/server/mocks.h"
#include "test/mocks/upstream/mocks.h"
#include "test/test_common/network_utility.h"
#include "test/test_common/utility.h"

#include "congestionlimiter/localcongestionlimiter_filter.h"
#include "congestionlimiter/config_factory.h"
#include "gtest/gtest.h"

using testing::_;
using ::testing::HasSubstr;
using ::testing::InSequence;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;

using namespace std::chrono_literals;

namespace Envoy {
namespace Http {
namespace CongestionLimiter {

const std::string config_yaml = R"EOF(
name: envoy.congestionlimiter
typed_config:
  "@type": type.googleapis.com/envoy.config.filter.http.localcongestionlimiter_filter.v3.LocalCongestionLimiter
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
      - destination_cluster: {}
      - request_headers:
          header_name: "x-provoke-ebay-edge-response"
          descriptor_key: provoke_response
          skip_if_absent: true
    descriptors:
      - key: header_match
      # key: path_match # TODO[UFES-8084]: Use after 1.24.
        value: testpath-trigger
        descriptors:
        - key: destination_cluster
          value: "block-cluster"
          limit: 
            fixed: { limit: 0 }
        - key: destination_cluster
          value: "shadow-cluster"
          limit: 
            fixed: { limit: 1 }
          shadow_mode: true
        - key: destination_cluster
          # value: No value specified - match any!
          limit: 
            fixed: { limit: 10 }
          descriptors:
          - key: provoke_response
            limit: 
              fixed: { limit: 0 }
    response_policy: test_response_policy
  response_policies:
    - name: test_response_policy
      responses:
        - match:
            header:
              name: "x-provoke-ebay-edge-response"
              exact_match: monitor
            # string_match:  # TODO[UFES-8084]: Use after 1.24.
            #   exact: monitor
            #   ignore_case: true
          action:
            monitor: true
        - match:
            header:
              name: ":path"
              prefix_match: /testpath/static-response
            # string_match:  # TODO[UFES-8084]: Use after 1.24.
            #   prefix: /testpath/static-response
            #   ignore_case: true
          action:
            static_response:
              response_code: 429
              source:
                inline_bytes: "H4sIAKqafmMAA3PLLy1SyCjNSylKTVEoKU/NK6nUzcvMS+UCAHYq0qsZAAAA"
)EOF";

class LocalCongestionLimiterTest : public testing::TestWithParam<Network::Address::IpVersion>,
                                public Envoy::ConcurrencyTestBase {
public:
  LocalCongestionLimiterTest()
      : ConcurrencyTestBase(Http::CodecClient::Type::HTTP1, GetParam()) {
    // Set this to a high number during debugging.
    // This is a wall-clock timeout that can kill your debugging session.
    // concurrency_request_timeout_ = 999s;
    default_request_headers_ = Http::TestRequestHeaderMapImpl{{":method", "GET"},
                                                     {":path", "/testpath/static-response"},
                                                     {":scheme", "http"},
                                                     {":authority", "ebay.com"},
                                                     {"x-forwarded-for", "10.0.0.1"}};
  }
  ~LocalCongestionLimiterTest() { cleanup(); }
  void initializeFilter(const std::string& yaml);
  void createUpstreams() override;
  void cleanup();
  void waitForUpstreamResponse(std::string);

protected:
  // ConcurrencyTestBase methods
  void verifyResponseBlocked(IntegrationStreamDecoderPtr response);
  void waitForSingleRequestBlocked();

public:
  IntegrationStreamDecoderPtr response_;
  FakeHttpConnectionPtr upstream_connection_;
  FakeStreamPtr upstream_request_;
  IntegrationStreamDecoderPtr upstream_response_;
};

void LocalCongestionLimiterTest::createUpstreams() {
  HttpIntegrationTest::createUpstreams();

  // Create an upstream called upstream0
  addFakeUpstream(FakeHttpConnection::Type::HTTP1);
  registerPort("upstream0", fake_upstreams_.back()->localAddress()->ip()->port());
}

void LocalCongestionLimiterTest::cleanup() {
  codec_client_->close();
  // Clean up upstream0
  if (upstream_connection_ != nullptr) {
    EXPECT_TRUE(upstream_connection_->close());
    EXPECT_TRUE(upstream_connection_->waitForDisconnect());
  }
  cleanupUpstreamAndDownstream();
}

void LocalCongestionLimiterTest::initializeFilter(const std::string& yaml) {
  config_helper_.addFilter(yaml);

  // Declare that upstream0 is an upstream cluster to Envoy
  config_helper_.addConfigModifier([](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
    auto* upstream0 = bootstrap.mutable_static_resources()->add_clusters();
    upstream0->MergeFrom(bootstrap.static_resources().clusters()[0]);
    upstream0->set_name("upstream0");
  });

  // Create a route /testpath that goes to upstream0
  config_helper_.addConfigModifier([](
    envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager& hcm) {
      hcm.mutable_route_config()
          ->mutable_virtual_hosts(0)
          ->mutable_routes(0)
          ->mutable_match()
          ->set_prefix("/xyz/abc");
      // hcm.mutable_bugfix_reverse_encode_order()->set_value(false);

      auto* new_route = hcm.mutable_route_config()->mutable_virtual_hosts(0)->add_routes();
      auto* route_match = new_route->mutable_match();
      route_match->set_prefix("/testpath");
      new_route->mutable_route()->set_cluster("upstream0");
    });
  initialize();
}

// Fake upstream will respond with the response code we set in this method
void LocalCongestionLimiterTest::waitForUpstreamResponse(std::string resp_code) {
  // Envoy is expected to forward the request to upstream
  if (!upstream_connection_) {
    ASSERT_TRUE(fake_upstreams_.back()->waitForHttpConnection(*dispatcher_, upstream_connection_));
  }
  ASSERT_TRUE(upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  Http::TestRequestHeaderMapImpl respHeaders = Http::TestRequestHeaderMapImpl{{":status", resp_code}};
  upstream_request_->encodeHeaders(respHeaders, false);
  upstream_request_->encodeData(1024, true);
}

void LocalCongestionLimiterTest::waitForSingleRequestBlocked(){
  //TODO<kburek>: wait for single request blocked by counter or whatever.
}

void LocalCongestionLimiterTest::verifyResponseBlocked(IntegrationStreamDecoderPtr) {
  //TODO<kburek>: verify response blocked by http code or whatever.
}

INSTANTIATE_TEST_SUITE_P(IpVersions, LocalCongestionLimiterTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);


TEST_P(LocalCongestionLimiterTest, CongestionLimiterAllowsRequest) {
  initializeFilter(config_yaml);

  codec_client_ = makeHttpConnection(lookupPort("http"));
  response_ = codec_client_->makeHeaderOnlyRequest(default_request_headers_);
  
  waitForUpstreamResponse("200");

  // Check counters
  test_server_->waitForCounterEq("http.config_test.edge_localcongestionlimiter.test_limit.described", 1, 10s);
  test_server_->waitForCounterGe("http.config_test.localcongestionlimiter_descriptor_entry_count", 1);
  EXPECT_EQ(1, test_server_->counter("http.config_test.edge_localcongestionlimiter.test_limit.under_limit")->value());
  EXPECT_FALSE(test_server_->counter("http.config_test.edge_localcongestionlimiter.test_limit.over_limit"));

  // Wait for response at client end
  response_->waitForEndStream();
  ASSERT_TRUE(response_->complete());
  EXPECT_EQ("200", response_->headers().Status()->value().getStringView());
}

TEST_P(LocalCongestionLimiterTest, CongestionLimiterNotInvoked) {
  initializeFilter(config_yaml);

  // Request which is evaluated but no descriptors should be generated
  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  Http::TestRequestHeaderMapImpl noDescriptorReqHeaders =
      Http::TestRequestHeaderMapImpl{{":method", "GET"},
                                     {":path", "/pqrs"},
                                     {":scheme", "http"},
                                     {":authority", "ebay.com"},
                                     {"x-forwarded-for", "10.0.0.1"}};
  response_ = codec_client_->makeHeaderOnlyRequest(noDescriptorReqHeaders);

  // Check counters, no increment of generated descriptors.
  test_server_->waitForCounterEq("http.config_test.edge_localcongestionlimiter.test_limit.described", 1, 10s);
  EXPECT_EQ(1, test_server_->counter("http.config_test.localcongestionlimiter_generated_empty_descriptors")->value());
  EXPECT_FALSE(test_server_->counter("http.config_test.localcongestionlimiter_descriptor_entry_count"));
  EXPECT_FALSE(test_server_->counter("http.config_test.edge_localcongestionlimiter.test_limit.under_limit"));
  EXPECT_FALSE(test_server_->counter("http.config_test.edge_localcongestionlimiter.test_limit.over_limit"));
  // Wait for response at client end
  response_->waitForEndStream();
  ASSERT_TRUE(response_->complete());
  // /pqrs will generate NR response from Envoy
  EXPECT_EQ("404", response_->headers().Status()->value().getStringView());
}

TEST_P(LocalCongestionLimiterTest, CongestionLimiterBlocksRequest) {
  initializeFilter(config_yaml);

  // Request that hits a policy and is over limit
  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  default_request_headers_.addCopy("x-provoke-ebay-edge-response", "true");
  response_ = codec_client_->makeHeaderOnlyRequest(default_request_headers_);
  
  waitForUpstreamResponse("200");

  // Check counters
  test_server_->waitForCounterGe("http.config_test.localcongestionlimiter_descriptor_entry_count", 1, 10s);
  EXPECT_EQ(1, test_server_->counter("http.config_test.edge_localcongestionlimiter.test_limit.described")->value());
  EXPECT_EQ(1, test_server_->counter("http.config_test.edge_localcongestionlimiter.test_limit.over_limit")->value());

  // Wait for response at client end
  response_->waitForEndStream();
  ASSERT_TRUE(response_->complete());
  EXPECT_EQ("429", response_->headers().Status()->value().getStringView());
}

/*
TEST_P(LocalCongestionLimiterTest, CongestionLimiterMonitorThreshold) {
  initializeFilter(config_yaml);

  // Request that hits a policy
  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  // TODO<kburek> figure out why you can't send multiple requests at once to the fake upstream.
  //              then we can increase the monitor limit to see one request under and one request over limit.
  sendRequests(1, 1, *fake_upstreams_.back());
  respondToRequest(true);
  // Request that hits a policy and is over limit
  default_request_headers_.addCopy("x-provoke-ebay-edge-response", "monitor");
  sendRequests(1, 1, *fake_upstreams_.back());
  respondToRequest(false);

  // Check counters
  test_server_->waitForCounterEq("http.config_test.localcongestionlimiter_descriptor_entry_count", 5);
  test_server_->waitForCounterEq("http.config_test.edge_localcongestionlimiter.test_limit.described", 2);
  test_server_->waitForCounterEq("http.config_test.edge_localcongestionlimiter.test_limit.under_limit", 1);
  test_server_->waitForCounterEq("http.config_test.edge_localcongestionlimiter.test_limit.over_limit", 1);
  test_server_->waitForCounterEq("http.config_test.edge_localcongestionlimiter.test_response_policy", 1);
  test_server_->waitForCounterEq("http.config_test.edge_localcongestionlimiter.test_response_policy.monitor", 1);
}
*/

/*
TEST_P(LocalCongestionLimiterTest, CongestionLimiterRejectsMissingResponsePolicy) {
}
*/


} // namespace CongestionLimiter
} // namespace Http
} // namespace Envoy
