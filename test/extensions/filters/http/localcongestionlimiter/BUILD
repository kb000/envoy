load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

envoy_package()


envoy_cc_test(
    name = "integration_test",
    srcs = ["localcongestionlimiter_filter_integration_test.cc"],
    external_deps = ["abseil_optional"],
    repository = "@envoy",
    deps = [
        "//congestionlimiter:localcongestionlimiter_config_lib",
        "//congestionlimiter:localcongestionlimiter_filter_lib",
        "//test/common:concurrency_test_base_lib",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/common/http:headers_lib",
        "@envoy//test/integration:http_integration_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy//test/mocks/http:http_mocks",
        "@envoy//test/mocks/server:server_mocks",
        "@envoy//test/mocks/upstream:upstream_mocks",
    ],
)

envoy_cc_test(
    name = "unit_test",
    srcs = ["localcongestionlimiter_filter_unit_test.cc"],
    repository = "@envoy",
    deps = [
        "//congestionlimiter:localcongestionlimiter_config_lib",
        "//congestionlimiter:localcongestionlimiter_filter_lib",
        "//congestionlimiter:congestionlimitengine_lib",
        "@envoy//include/envoy/http:codes_interface",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/common/stats:isolated_store_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy//test/test_common:logging_lib",
        "@envoy//test/mocks/http:http_mocks",
        "@envoy//test/mocks/server:factory_context_mocks",
    ],
)

envoy_cc_test(
    name = "engine_unit_test",
    srcs = ["localcongestionlimiter_engine_unit_test.cc"],
    repository = "@envoy",
    deps = [
        "//congestionlimiter:congestionlimitengine_lib",
        "@envoy//include/envoy/http:codes_interface",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/common/stats:isolated_store_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy//test/test_common:logging_lib",
        "@envoy//test/mocks/http:http_mocks",
        "@envoy//test/mocks/server:factory_context_mocks",
    ],
)
