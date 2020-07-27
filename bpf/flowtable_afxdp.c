/*
 * Copyright (c) 2020 NTT Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* linux/types.h is necessary for bpf_helpers.h as it's not self-contained so
 * that we can alternatively choose vmlinux.h auto-generated from BTF. */
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

/* Workaround for incorrect macros for bpf in stdint.h */
#include <stdint.h>
#include "bpf_workaround.h"

#include "bpf_compiler.h"
#include "bpf_miniflow.h"
#include "bpf_netlink.h"
#include "netdev-offload-xdp.h"
#include "packets.h"
#include "util.h"

/* Supported keys. Need to keep same 64-align as struct flow for miniflow */
struct xdp_flow {
    struct eth_addr dl_dst;
    struct eth_addr dl_src;
    ovs_be16 dl_type;
    uint8_t pad1[2];

    union flow_vlan_hdr vlans[1];
    uint8_t pad2[4];

    ovs_be32 nw_src;
    ovs_be32 nw_dst;

    uint8_t pad3[4];
    uint8_t nw_frag;
    uint8_t nw_tos;
    uint8_t nw_ttl;
    uint8_t nw_proto;

    ovs_be16 tp_src;
    ovs_be16 tp_dst;
    uint8_t pad4[4];
};

/* Size of xdp_flow must be 64-aligned for key comparison */
BUILD_ASSERT_DECL(sizeof(struct xdp_flow) % sizeof(uint64_t) == 0);

#define XDP_FLOW_U64S (sizeof(struct xdp_flow) / sizeof(uint64_t))

#define XDP_MAX_SUBTABLE_FLOWS 1024
#define XDP_MAX_ACTIONS_LEN 256
#define XDP_MAX_ACTIONS 32

/* Actual key in each subtable. miniflow map is omitted as it's identical to
 * mask map */
struct xdp_flow_key {
    /* Actually we can use smaller key than XDP_FLOW_U64S to minimize hash
     * table search cost. It's possible because we rarely need all of
     * combinations of flow keys. OVS XDP offload can properly handle
     * smaller one. */
    uint64_t miniflow_buf[XDP_FLOW_U64S];
    /* Dummy. keep xdp_flow details in BTF */
    struct xdp_flow _flow[];
};

/* Value for subtable mask array */
struct xdp_subtable_mask {
    struct xdp_subtable_mask_header header;
    uint64_t buf[XDP_FLOW_U64S];
};

/* miniflow for packet */
struct xdp_miniflow {
    struct miniflow mf;
    uint64_t miniflow_buf[XDP_FLOW_U64S];
};

/* Used when the action only modifies the packet */
#define _XDP_ACTION_CONTINUE -1

/* Supported actions */
/* NOTE: This size should be uint16_t but needs to be int as kernel has a bug
 * in btf_enum_check_member() that assumes enum size is sizeof(int), which
 * causes an error when loading BTF if we use uint16_t here */
enum action_attrs : uint32_t {
    XDP_ACTION_OUTPUT = OVS_ACTION_ATTR_OUTPUT,
    XDP_ACTION_PUSH_VLAN = OVS_ACTION_ATTR_PUSH_VLAN,
    XDP_ACTION_POP_VLAN = OVS_ACTION_ATTR_POP_VLAN,
};

struct xdp_flow_actions {
    struct xdp_flow_actions_header header;
    uint8_t data[XDP_MAX_ACTIONS_LEN - sizeof(struct xdp_flow_actions_header)];
};

/* A struct to inform vswitchd of metadata like supported keys/actions */
struct xdp_meta_info {
    __type(supported_keys, struct xdp_flow);
    __type(supported_actions, enum action_attrs);
    __uint(max_actions, XDP_MAX_ACTIONS);
} meta_info SEC(".ovs_meta");


/* Map definitions */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, uint32_t);
    __type(value, long);
} debug_stats SEC(".maps");

/* Temporary storage for packet miniflow. Need this because verifier does not
 * allow access to array variable in stack with variable index. Such access
 * happens in mask_key() */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct xdp_miniflow);
} pkt_mf_tbl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1); /* This should be redefined by userspace */
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, XDP_MAX_PORTS);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} output_map SEC(".maps");

/* Head index for subtbl_masks list */
/* TODO: Use global variable */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, int);
} subtbl_masks_hd SEC(".maps");

/* Information about subtable mask. A list implemented using array */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, XDP_MAX_SUBTABLES);
    __type(key, uint32_t);
    __type(value, struct xdp_subtable_mask);
} subtbl_masks SEC(".maps");

/* Template for subtable hash-map. This will be used in userspace to create
 * flow_table array-of-maps. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, XDP_MAX_SUBTABLE_FLOWS);
    __type(key, struct xdp_flow_key);
    __type(value, struct xdp_flow_actions);
} subtbl_template SEC(".maps");

/* Array-of-maps whose entry contains subtable hash-map. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDP_MAX_SUBTABLES);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
} flow_table SEC(".maps");


static inline void
account_debug(int idx)
{
    long *cnt;

    cnt = bpf_map_lookup_elem(&debug_stats, &idx);
    if (cnt) {
        *cnt += 1;
    }
}

static inline void
account_action(enum action_attrs act)
{
    account_debug(act + 1);
}

/* Derived from xsk_load_xdp_prog() in libbpf */
static inline int
upcall(struct xdp_md *ctx)
{
    int ret, index = ctx->rx_queue_index;

    ret = bpf_redirect_map(&xsks_map, index, XDP_ABORTED);
    if (ret > 0) {
        return ret;
    }

    /* Fallback for kernel <= 5.3 not supporting default action in flags */
    if (bpf_map_lookup_elem(&xsks_map, &index)) {
        return bpf_redirect_map(&xsks_map, index, 0);
    }

    return XDP_ABORTED;
}

static inline int
action_output(int tx_port)
{
    account_action(XDP_ACTION_OUTPUT);

    return bpf_redirect_map(&output_map, tx_port, 0);
}

static inline int
action_vlan_push(struct xdp_md *ctx,
                 const struct ovs_action_push_vlan *vlan)
{
    struct vlan_eth_header *veh;
    void *data, *data_end;
    ovs_be16 tpid, tci;

    account_action(XDP_ACTION_PUSH_VLAN);

    tpid = vlan->vlan_tpid;
    tci = vlan->vlan_tci;

    if (bpf_xdp_adjust_head(ctx, -VLAN_HEADER_LEN)) {
        return XDP_DROP;
    }

    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;
    if (data + VLAN_ETH_HEADER_LEN > data_end) {
        return XDP_DROP;
    }

    __builtin_memmove(data, data + VLAN_HEADER_LEN, 2 * ETH_ADDR_LEN);
    veh = data;
    veh->veth_type = tpid;
    veh->veth_tci = tci & htons(~VLAN_CFI);

    return _XDP_ACTION_CONTINUE;
}

static inline int
action_vlan_pop(struct xdp_md *ctx)
{
    struct vlan_eth_header *veh;
    void *data, *data_end;

    account_action(XDP_ACTION_POP_VLAN);

    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;
    if (data + VLAN_ETH_HEADER_LEN > data_end) {
        return _XDP_ACTION_CONTINUE;
    }

    veh = data;
    if (!eth_type_vlan(veh->veth_type)) {
        return _XDP_ACTION_CONTINUE;
    }

    __builtin_memmove(data + VLAN_HEADER_LEN, data, 2 * ETH_ADDR_LEN);
    if (bpf_xdp_adjust_head(ctx, VLAN_HEADER_LEN)) {
        return XDP_DROP;
    }

    return _XDP_ACTION_CONTINUE;
}

/* TODO: Add more actions */


struct nw_params {
    union {
        ovs_be32 params;
        struct {
            uint8_t nw_frag;
            uint8_t nw_tos;
            uint8_t nw_ttl;
            uint8_t nw_proto;
        };
    };
};

static inline int
parse_ipv4(void *data, uint64_t *nh_off, void *data_end,
           struct bpf_mf_ctx *mf_ctx, struct nw_params *nw_params)
{
    struct ip_header *ip = data + *nh_off;

    if (ip + 1 > data_end) {
        return 1;
    }

    /* Linux network drivers ensure that IP header is 4-byte aligned or
     * the platform can handle unaligned access */
    miniflow_push_be32(mf_ctx, nw_src, *(ovs_be32 *)(void *)&ip->ip_src);
    miniflow_push_be32(mf_ctx, nw_dst, *(ovs_be32 *)(void *)&ip->ip_dst);

    if (OVS_UNLIKELY(IP_IS_FRAGMENT(ip->ip_frag_off))) {
        nw_params->nw_frag = FLOW_NW_FRAG_ANY;
        if (ip->ip_frag_off & htons(IP_FRAG_OFF_MASK)) {
            nw_params->nw_frag |= FLOW_NW_FRAG_LATER;
        }
    } else {
        nw_params->nw_frag = 0;
    }
    nw_params->nw_tos = ip->ip_tos;
    nw_params->nw_ttl = ip->ip_ttl;
    nw_params->nw_proto = ip->ip_proto;

    *nh_off += IP_IHL(ip->ip_ihl_ver) * 4;

    return 0;
}

static inline int
xdp_miniflow_extract(struct xdp_md *ctx, struct xdp_miniflow *pkt_mf)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_header *eth = data;
    struct vlan_header *vlan = NULL;
    ovs_be16 dl_type;
    uint64_t nh_off;
    struct nw_params nw_params;
    struct bpf_mf_ctx mf_ctx = { {{ 0 }}, (uint64_t *)&pkt_mf->miniflow_buf };

    nh_off = sizeof *eth;
    if (data + nh_off > data_end) {
        return 1;
    }

    miniflow_push_macs(&mf_ctx, dl_dst, &eth->eth_dst);

    if (eth_type_vlan(eth->eth_type)) {
        vlan = data + nh_off;
        nh_off += sizeof(*vlan);
        if (data + nh_off > data_end) {
            return 1;
        }
        dl_type = vlan->vlan_next_type;
    } else {
        dl_type = eth->eth_type;
    }
    miniflow_push_be16(&mf_ctx, dl_type, dl_type);
    miniflow_pad_to_64(&mf_ctx, dl_type);

    if (vlan) {
        const ovs_16aligned_be32 *qp;
        union flow_vlan_hdr vlan_hdr;

        qp = (ovs_16aligned_be32 *)&eth->eth_type;
        vlan_hdr.qtag = get_16aligned_be32(qp);
        vlan_hdr.tci |= htons(VLAN_CFI);
        miniflow_push_be32(&mf_ctx, vlans, vlan_hdr.qtag);
        miniflow_push_be32_(&mf_ctx,
                            offsetof(struct flow, vlans) + sizeof(ovs_be32),
                            0);
    }

    if (dl_type == htons(ETH_TYPE_IP)) {
        if (parse_ipv4(data, &nh_off, data_end, &mf_ctx, &nw_params)) {
            return 1;
        }
    } else {
        goto out;
    }
    miniflow_pad_from_64(&mf_ctx, nw_frag);
    miniflow_push_be32(&mf_ctx, nw_frag, &nw_params.params);

    if (nw_params.nw_proto == IPPROTO_TCP) {
        struct tcp_header *tcp = data + nh_off;

        if (tcp + 1 > data_end) {
            return 1;
        }

        miniflow_push_be16(&mf_ctx, tp_src, tcp->tcp_src);
        miniflow_push_be16(&mf_ctx, tp_dst, tcp->tcp_dst);
    } else if (nw_params.nw_proto == IPPROTO_UDP) {
        struct udp_header *udp = data + nh_off;

        if (udp + 1 > data_end) {
            return 1;
        }

        miniflow_push_be16(&mf_ctx, tp_src, udp->udp_src);
        miniflow_push_be16(&mf_ctx, tp_dst, udp->udp_dst);
    }
out:
    pkt_mf->mf.map = mf_ctx.map;
    return 0;
}

#define for_each_subtable_mask(subtable_mask, head, idx, cnt) \
    for (subtable_mask = bpf_map_lookup_elem(&subtbl_masks, (head)), \
         idx = *(head), cnt = 0; \
         subtable_mask != NULL && cnt < XDP_MAX_SUBTABLES; \
         idx = subtable_mask->header.next, \
         subtable_mask = bpf_map_lookup_elem(&subtbl_masks, &idx), cnt++)

/* Returns false if an error happens */
static inline int
mask_key(uint64_t *mkey, const struct miniflow *pkt_mf,
         const struct xdp_subtable_mask_header *tbl_mask)
{
    const struct miniflow *tbl_mf = &tbl_mask->mask.masks;
    const uint64_t *tbl_blocks = miniflow_get_values(tbl_mf);
    const uint64_t *pkt_blocks = miniflow_get_values(pkt_mf);
    uint64_t tbl_mf_bits = tbl_mf->map.bits[0];
    uint64_t pkt_mf_bits = pkt_mf->map.bits[0];
    uint8_t tbl_mf_bits_u0 = tbl_mask->mf_bits_u0;
    uint8_t tbl_mf_bits_u1 = tbl_mask->mf_bits_u1;
    unsigned int pkt_ofs = 0;
    int i = 0;

    /* This sensitive loop easily exceeds verifier limit 1M insns so
     * need to be careful when modifying.
     * E.g. increasing XDP_FLOW_U64S by adding keys to struct xdp_flow
     * increases verifier cost and may be rejected due to 1M insns exceeds */
    for (; i < tbl_mf_bits_u0 + tbl_mf_bits_u1 && i < XDP_FLOW_U64S; i++) {
        uint64_t mf_mask;
        uint64_t idx_bits;
        unsigned int pkt_idx;
        uint64_t lowest_bit;

        if (i == tbl_mf_bits_u0) {
            tbl_mf_bits = tbl_mf->map.bits[1];
            pkt_mf_bits = pkt_mf->map.bits[1];
            pkt_ofs = count_1bits(pkt_mf->map.bits[0]);
        }

        lowest_bit = tbl_mf_bits & -tbl_mf_bits;
        tbl_mf_bits &= ~lowest_bit;
        if (!(lowest_bit & pkt_mf_bits)) {
            mkey[i] = 0;
            continue;
        }
        mf_mask = lowest_bit - 1;
        idx_bits = mf_mask & pkt_mf_bits;
        pkt_idx = count_1bits(idx_bits) + pkt_ofs;
        if (pkt_idx >= XDP_FLOW_U64S) {
            /* xdp flow api provider (userspace) BUG */
            return false;
        }

        mkey[i] = pkt_blocks[pkt_idx] & tbl_blocks[i];
    }

    return true;
}

SEC("xdp") int
flowtable_afxdp(struct xdp_md *ctx)
{
    struct xdp_miniflow *pkt_mf;
    struct xdp_subtable_mask *subtable_mask;
    int *head;
    struct xdp_flow_actions *xdp_actions = NULL;
    int cnt, i, idx, zero = 0;
    struct nlattr *attrs;
    size_t actions_len, offset;
    void *start, *end;

    account_debug(0);

    head = bpf_map_lookup_elem(&subtbl_masks_hd, &zero);
    if (!head) {
        return XDP_ABORTED;
    }
    if (*head == XDP_SUBTABLES_TAIL) {
        /* Offload not enabled */
        goto upcall;
    }

    /* Get temporary storage for storing packet miniflow */
    pkt_mf = bpf_map_lookup_elem(&pkt_mf_tbl, &zero);
    if (!pkt_mf) {
        return XDP_ABORTED;
    }

    /* Extract miniflow from packet */
    if (xdp_miniflow_extract(ctx, pkt_mf)) {
        return XDP_DROP;
    }

    /* Lookup each subtable */
    for_each_subtable_mask(subtable_mask, head, idx, cnt) {
        struct xdp_flow_key mkey = { 0 };
        void *subtable;

        subtable = bpf_map_lookup_elem(&flow_table, &idx);
        if (!subtable) {
            return XDP_ABORTED;
        }

        if (!mask_key(mkey.miniflow_buf, &pkt_mf->mf,
                      &subtable_mask->header)) {
            continue;
        }

        xdp_actions = bpf_map_lookup_elem(subtable, &mkey);
        if (xdp_actions) {
            break;
        }
    }

    if (!xdp_actions) {
        /* Flow entry miss */
upcall:
        return upcall(ctx);
    }

    /* Execute actions */
    actions_len = xdp_actions->header.actions_len;
    if (actions_len > XDP_MAX_ACTIONS_LEN -
                      sizeof(struct xdp_flow_actions_header)) {
        return XDP_ABORTED;
    }
    attrs = xdp_flow_actions(&xdp_actions->header);
    start = xdp_actions;
    end = (void *)attrs + actions_len;
    BPF_MAP_NL_ATTR_FOR_EACH (offset, attrs, start, end, i, XDP_MAX_ACTIONS,
                              XDP_MAX_ACTIONS_LEN) {
        uint16_t type;
        int act;
        struct nlattr *nla;

        if (offset > XDP_MAX_ACTIONS_LEN - sizeof(struct nlattr)) {
            return XDP_ABORTED;
        }
        type = bpf_nl_attr_type((struct nlattr *)(start + offset));

        switch ((enum action_attrs)type) {
        case XDP_ACTION_OUTPUT:
            bpf_compiler_reg_barrier(offset);
            if (offset > XDP_MAX_ACTIONS_LEN - sizeof(struct nlattr) -
                         sizeof(int)) {
                return XDP_ABORTED;
            }
            nla = start + offset;
            return action_output(*(int *)bpf_nl_attr_get(nla));
        case XDP_ACTION_PUSH_VLAN:
            bpf_compiler_reg_barrier(offset);
            if (offset > XDP_MAX_ACTIONS_LEN - sizeof(struct nlattr) -
                         sizeof(struct ovs_action_push_vlan)) {
                return XDP_ABORTED;
            }
            nla = start + offset;
            act = action_vlan_push(ctx, bpf_nl_attr_get(nla));
            break;
        case XDP_ACTION_POP_VLAN:
            act = action_vlan_pop(ctx);
            break;
        default:
            return XDP_ABORTED;
        }
        if (act != _XDP_ACTION_CONTINUE) {
            return act;
        }
    }

    account_debug(1);
    return XDP_DROP;
}

char _license[] SEC("license") = "Apache-2.0";
