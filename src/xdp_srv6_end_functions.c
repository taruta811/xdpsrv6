#define KBUILD_MODNAME "xdp_srv6_end_functions"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/seg6.h>
#include <uapi/linux/seg6_local.h>
#include <net/ipv6.h>

#define MAX_END_FUNCTION_ENTRIES 256

struct end_function {
    __u8 function;
};

BPF_TABLE("hash", struct in6_addr, struct end_function, end_function_table, MAX_END_FUNCTION_ENTRIES);

static void swap_macaddr(struct ethhdr *eth) {
    unsigned char tmp[ETH_ALEN];

    memcpy(tmp, &eth->h_source, sizeof(unsigned char) * ETH_ALEN);
    memcpy(&eth->h_source, &eth->h_dest, sizeof(unsigned char) * ETH_ALEN);
    memcpy(&eth->h_dest, tmp, sizeof(unsigned char) * ETH_ALEN);
}

static int handle_end(struct xdp_md *xdp) {
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth = data;
    struct ipv6hdr *hdr = data + sizeof(struct ethhdr);
    struct ipv6_sr_hdr *srhdr = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

    if (
        data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct ipv6_sr_hdr) > data_end ||
        srhdr->segments_left == 0
    ) {
        return XDP_DROP;
    }

    swap_macaddr(eth);
    srhdr->segments_left--;
    if ((void *)(long)srhdr + sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr) * (srhdr->segments_left + 1) > data_end) {
        return XDP_DROP;
    }
    memcpy(&hdr->daddr, &srhdr->segments[srhdr->segments_left], sizeof(struct in6_addr));

    return XDP_TX;
}

int xdp_srv6_handle_end_function(struct xdp_md *xdp) {
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth = data;
    struct ipv6hdr *hdr = data + sizeof(struct ethhdr);
    struct end_function *ef;

    if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end) {
        return XDP_DROP;
    }

    if (eth->h_proto != htons(ETH_P_IPV6) || hdr->nexthdr != NEXTHDR_ROUTING) {
        return XDP_PASS;
    }

    ef = end_function_table.lookup(&hdr->daddr);
    if (!ef) {
        return XDP_PASS;
    }

    switch(ef->function) {
        case SEG6_LOCAL_ACTION_END:
            return handle_end(xdp);
    }

    return XDP_DROP;
}
