package(default_visibility = ["//visibility:public"])
load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

envoy_cc_library(
    name = "localcongestionlimiter_config_lib",
    srcs = ["config_factory.cc"],
    hdrs = ["config_factory.h"],
    repository = "@envoy",
    deps = [
        ":localcongestionlimiter_filter_lib",
        "@envoy//include/envoy/registry",
        "@envoy//source/extensions/filters/http:well_known_names",
        "@envoy//source/extensions/filters/http/common:factory_base_lib",
    ],
)

envoy_cc_library(
    name = "localcongestionlimiter_filter_lib",
    srcs = ["localcongestionlimiter_filter.cc"],
    hdrs = ["localcongestionlimiter_filter.h"],
    repository = "@envoy",
    deps = [
        ":congestionlimitengine_lib",
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/stats:stats_macros",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/http:utility_lib",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/router:router_ratelimit_lib",
        "@envoy//source/extensions/filters/http/common:factory_base_lib",
        "@ufes_api//envoy/config/filter/http/localcongestionlimiter_filter/v3:pkg_cc_proto",
        "@ufes_api//envoy/config/filter/http/circuitbreaker_filter/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "congestionlimitengine_lib",
    srcs = ["congestionlimitengine.cc", "responseengine.cc"],
    hdrs = ["congestionlimitengine.h", "responseengine.h"],
    repository = "@envoy",
    deps = [
        "//actions:actions_lib",
        "//matchers:cb_matchers_lib",
        "//circuitbreaker:circuitbreaker_limit_interface",
        "//circuitbreaker:circuitbreaker_engine_lib",
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/stats:stats_macros",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/http:utility_lib",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/router:router_ratelimit_lib",
        "@envoy//source/extensions/filters/http/common:factory_base_lib",
        "@ufes_api//envoy/config/filter/http/localcongestionlimiter_filter/v3:pkg_cc_proto",
        "@ufes_api//envoy/config/filter/http/circuitbreaker_filter/v3:pkg_cc_proto",
    ],
)
