load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "nested",
    srcs = [
        "nested.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "nested_test",
    size = "small",
    srcs = [
        "nested_test.go",
    ],
    library = ":nested",
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)
