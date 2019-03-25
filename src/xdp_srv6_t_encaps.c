#define KBUILD_MODNAME "xdp_srv6_t_encaps"
#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/seg6.h>

#define MAX_TRANSIT_ENTRIES 256
#define MAX_SEGMENTS 20

#define NEXTHDR_ROUTING 43

struct transit_behavior {
    int mode;
    int segment_length;
    struct in6_addr saddr;
    struct in6_addr segments[MAX_SEGMENTS];
};

BPF_TABLE("hash", __u32, struct transit_behavior, transit_table_v4, MAX_TRANSIT_ENTRIES);
BPF_TABLE("hash", struct in6_addr, struct transit_behavior, transit_table_v6, MAX_TRANSIT_ENTRIES);


static inline int handle_ipv4(struct xdp_md *xdp) {
    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;
    struct transit_behavior *tb;
    struct ethhdr *old_eth, *new_eth;
    struct iphdr *ihdr = data + sizeof(struct ethhdr);
    struct ipv6hdr *hdr;
    struct ipv6_sr_hdr *srh;
    __u32 srh_len, tot_len, i, inner_len;

    if ((long)ihdr + sizeof(struct iphdr) > (long)data_end) {
        return XDP_DROP;
    }
    inner_len = sizeof(struct ethhdr) + ihdr->tot_len;

    tb = transit_table_v4.lookup(&ihdr->daddr);
    if (!tb) {
        return XDP_DROP;
    }

    srh_len = sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr) * tb->segment_length;
    if (srh_len < sizeof(struct ipv6_sr_hdr) || srh_len > sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr) * MAX_SEGMENTS) {
        return XDP_DROP;
    }
    if(bpf_xdp_adjust_head(xdp, 0 - (int)(sizeof(struct ipv6hdr) + srh_len))) {
        return XDP_DROP;
    }

    data = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;

    // new_eth = data;
    hdr = (void *)data + sizeof(struct ethhdr);
    // old_eth = (void *)data + sizeof(struct ipv6hdr) + srh_len;
    // ihdr = (void *)old_eth + sizeof(struct ethhdr);

    // if ((void *)(hdr + sizeof(struct ipv6hdr) + srh_len + inner_len) > data_end) {
    if ((void *)(hdr + 1) > data_end) {
        return XDP_DROP;
    }
    // if ((long)hdr + sizeof(struct ipv6hdr) > (long)data_end) {
    //     return XDP_DROP;
    // }
    hdr->payload_len = srh_len + inner_len;
    hdr->nexthdr = NEXTHDR_ROUTING;
    memcpy(&hdr->saddr, &tb->saddr, sizeof(struct in6_addr));
    memcpy(&hdr->daddr, &tb->segments[0], sizeof(struct in6_addr));

    srh = (void *)data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    if ((void *)(srh + 4 * MAX_SEGMENTS) > data_end) {
        return XDP_DROP;
    }

    srh->nexthdr = IPPROTO_IPIP;
    srh->hdrlen = srh_len;
    srh->type = 4;
    srh->segments_left = tb->segment_length - 1;
    srh->first_segment = tb->segment_length - 1;
    srh->flags = 0;

#pragma clang loop unroll(full)
    for (i = 0; i < MAX_SEGMENTS; i++) {
        if (i > tb->segment_length) {
            break;
        }
        bpf_trace_printk("test");
        memcpy(&srh->segments[i], &tb->segments[i], sizeof(struct in6_addr));
    }

    return XDP_TX;
}


int xdp_srv6_t_encaps(struct xdp_md *xdp) {
    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;
    struct ethhdr *eth = data;
    __u16 h_proto;

    if ((long)eth + sizeof(struct ethhdr) > (long)data_end) {
        return XDP_DROP;
    }

    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_IP)) {
        return handle_ipv4(xdp);
    }

    return XDP_PASS;
}
