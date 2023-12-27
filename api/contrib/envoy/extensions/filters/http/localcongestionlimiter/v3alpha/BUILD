package(default_visibility = ["//visibility:public"])
load("//bazel:api_build_system.bzl", "api_proto_package")

api_proto_package(
    deps = [
        "@envoy_api//envoy/config/route/v3:pkg",
        "//envoy/config/filter/http/matcher/v3:pkg",
        "//envoy/config/filter/http/action/v3:pkg",
        "//envoy/config/filter/http/circuitbreaker_filter/v3:pkg",
    ],
)
