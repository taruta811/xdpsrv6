#define KBUILD_MODNAME "xdp_srv6_t_encaps"
#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/seg6.h>

#define MAX_TRANSIT_ENTRIES 256
#define MAX_SEGMENTS 5

#define NEXTHDR_ROUTING 43

struct transit_behavior {
    __u32 mode;
    __u32 segment_length;
    struct in6_addr saddr;
    struct in6_addr segments[MAX_SEGMENTS];
};

BPF_TABLE("hash", __u32, struct transit_behavior, transit_table_v4, MAX_TRANSIT_ENTRIES);
BPF_TABLE("hash", struct in6_addr, struct transit_behavior, transit_table_v6, MAX_TRANSIT_ENTRIES);


static inline int handle_ipv4(struct xdp_md *xdp) {
    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;
    struct transit_behavior *tb;
    struct ethhdr *old_eth = data, *new_eth;
    struct iphdr *ihdr = (void *)(data + sizeof(struct ethhdr));
    struct ipv6hdr *hdr;
    struct ipv6_sr_hdr *srh;
    __u8 srh_len;
    __u16 inner_len;
    __u32 i;

    if ((void*)(data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end) {
        return XDP_DROP;
    }
    inner_len = ntohs(ihdr->tot_len);

    tb = transit_table_v4.lookup(&ihdr->daddr);
    if (!tb) {
        return XDP_PASS;
    }

    if (tb->segment_length > MAX_SEGMENTS) {
        return XDP_DROP;
    }
    srh_len = sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr) * tb->segment_length;
    if(bpf_xdp_adjust_head(xdp, 0 - (int)(sizeof(struct ipv6hdr) + srh_len))) {
        return XDP_DROP;
    }

    data = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;

    // eth header
    new_eth= (void *)data;
    old_eth = (void *)(data + sizeof(struct ipv6hdr) + srh_len);
    if ((void *)((long)old_eth + sizeof(struct ethhdr)) > data_end) {
        return XDP_DROP;
    }
    if((void *)((long)new_eth + sizeof(struct ethhdr)) > data_end) {
        return XDP_DROP;
    }
    memcpy(&new_eth->h_source, &old_eth->h_dest, sizeof(unsigned char) * ETH_ALEN);
    memcpy(&new_eth->h_dest, &old_eth->h_source, sizeof(unsigned char) * ETH_ALEN);
    new_eth->h_proto = htons(ETH_P_IPV6);

    // outer IPv6 header
    hdr = (void *)data + sizeof(struct ethhdr);
    if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) > data_end) {
        return XDP_DROP;
    }
    hdr->version = 6;
    hdr->priority = 0;
    hdr->nexthdr = NEXTHDR_ROUTING;
    hdr->hop_limit = 64;
    hdr->payload_len = htons(srh_len + inner_len);
    memcpy(&hdr->saddr, &tb->saddr, sizeof(struct in6_addr));
    if (tb->segment_length == 0 || tb->segment_length > MAX_SEGMENTS) {
        return XDP_DROP;
    }
    memcpy(&hdr->daddr, &tb->segments[tb->segment_length - 1], sizeof(struct in6_addr));

    // SR header
    srh = (void *)hdr + sizeof(struct ipv6hdr);
    if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct ipv6_sr_hdr)) > data_end) {
        return XDP_DROP;
    }
    srh->nexthdr = IPPROTO_IPIP;
    srh->hdrlen = (srh_len / 8 - 1);
    srh->type = 4;
    srh->segments_left = tb->segment_length - 1;
    srh->first_segment = tb->segment_length - 1;
    srh->flags = 0;

    #pragma clang loop unroll(full)
    for (i = 0; i < MAX_SEGMENTS; i++) {
        if (i >= tb->segment_length) {
            break;
        }
        if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr) * (i + 1)) > data_end) {
            return XDP_DROP;
        }
        memcpy(&srh->segments[i], &tb->segments[i], sizeof(struct in6_addr));
    }

    return XDP_TX;
}

static inline int handle_ipv6(struct xdp_md *ctx) {
    // TODO
    return XDP_PASS;
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
    } else if (h_proto == htons(ETH_P_IPV6)) {
        return handle_ipv6(xdp);
    }

    return XDP_PASS;
}
