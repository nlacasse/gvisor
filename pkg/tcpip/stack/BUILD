load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "neighbor_entry_list",
    out = "neighbor_entry_list.go",
    package = "stack",
    prefix = "neighborEntry",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*neighborEntry",
        "Linker": "*neighborEntry",
    },
)

go_template_instance(
    name = "packet_buffer_list",
    out = "packet_buffer_list.go",
    package = "stack",
    prefix = "PacketBuffer",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*PacketBuffer",
        "Linker": "*PacketBuffer",
    },
)

go_library(
    name = "stack",
    srcs = [
        "conntrack.go",
        "dhcpv6configurationfromndpra_string.go",
        "forwarder.go",
        "icmp_rate_limit.go",
        "iptables.go",
        "iptables_targets.go",
        "iptables_types.go",
        "ndp.go",
        "neighbor_cache.go",
        "neighbor_entry.go",
        "neighbor_entry_list.go",
        "neighborstate_string.go",
        "nic.go",
        "nud.go",
        "packet_buffer.go",
        "packet_buffer_list.go",
        "rand.go",
        "registration.go",
        "route.go",
        "stack.go",
        "stack_global_state.go",
        "transport_demuxer.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/ilist",
        "//pkg/log",
        "//pkg/rand",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/hash/jenkins",
        "//pkg/tcpip/header",
        "//pkg/tcpip/ports",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/transport/tcpconntrack",
        "//pkg/waiter",
        "@org_golang_x_time//rate:go_default_library",
    ],
)

go_test(
    name = "stack_x_test",
    size = "medium",
    srcs = [
        "ndp_test.go",
        "nud_test.go",
        "stack_test.go",
        "transport_demuxer_test.go",
        "transport_test.go",
    ],
    deps = [
        ":stack",
        "//pkg/rand",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/loopback",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/transport/icmp",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
        "@com_github_google_go-cmp//cmp:go_default_library",
    ],
)

go_test(
    name = "stack_test",
    size = "small",
    srcs = [
        "forwarder_test.go",
        "neighbor_cache_test.go",
        "neighbor_entry_test.go",
        "nic_test.go",
    ],
    library = ":stack",
    deps = [
        "//pkg/sleep",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "@com_github_google_go-cmp//cmp:go_default_library",
        "@com_github_google_go-cmp//cmp/cmpopts:go_default_library",
    ],
)
