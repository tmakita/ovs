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

#include <config.h>

#include "netdev-offload-xdp.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <unistd.h>

#include "bpf-util.h"
#include "dpif.h"
#include "hash.h"
#include "netdev.h"
#include "netdev-offload-provider.h"
#include "netlink.h"
#include "odp-netlink.h"
#include "openvswitch/hmap.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_offload_xdp);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(100, 5);

static struct hmap ufid_to_xdp = HMAP_INITIALIZER(&ufid_to_xdp);

static struct ovs_mutex ufid_lock = OVS_MUTEX_INITIALIZER;

struct ufid_to_xdp_data {
    struct hmap_node ufid_node;
    ovs_u128 ufid;
    struct minimask mask;
    uint64_t mask_buf[FLOW_MAX_PACKET_U64S];
    struct miniflow flow;
    uint64_t flow_buf[FLOW_MAX_PACKET_U64S];
};

static struct hmap netdev_info_table = HMAP_INITIALIZER(&netdev_info_table);

struct netdev_info {
    struct hmap_node port_node;
    struct netdev *netdev;
    odp_port_t port;
    uint32_t devmap_idx;
    struct miniflow supported_keys;
    uint64_t supported_keys_buf[FLOW_MAX_PACKET_U64S];
    uint32_t supported_actions;
    uint32_t max_subtables;
    uint32_t subtable_mask_size;
    uint32_t key_size;
    uint32_t max_actions_len;
    uint32_t max_entries;
    int free_slot_top;
    int free_slots[XDP_MAX_SUBTABLES];
};

static struct hmap devmap_idx_table = HMAP_INITIALIZER(&devmap_idx_table);

struct devmap_idx_data {
    struct hmap_node node;
    int devmap_idx;
};


/* Free entry managemant for list implementation using array */

static void
init_subtbl_masks_free_slot(struct netdev_info *netdev_info)
{
    int i;
    int max_subtables = netdev_info->max_subtables;

    for (i = 0; i < max_subtables; i++) {
        netdev_info->free_slots[max_subtables - 1 - i] = i;
    }
    netdev_info->free_slot_top = max_subtables - 1;
}

static int
get_subtbl_masks_free_slot(const struct netdev_info *netdev_info, int *slot)
{
    if (netdev_info->free_slot_top < 0) {
        return ENOBUFS;
    }

    *slot = netdev_info->free_slots[netdev_info->free_slot_top];
    return 0;
}

static int
add_subtbl_masks_free_slot(struct netdev_info *netdev_info, int slot)
{
    if (netdev_info->free_slot_top >= netdev_info->max_subtables - 1) {
        VLOG_ERR_RL(&rl, "BUG: free_slot overflow: top=%d, slot=%d",
                    netdev_info->free_slot_top, slot);
        return EOVERFLOW;
    }

    netdev_info->free_slots[++netdev_info->free_slot_top] = slot;
    return 0;
}

static void
delete_subtbl_masks_free_slot(struct netdev_info *netdev_info, int slot)
{
    int top_slot;

    if (netdev_info->free_slot_top < 0) {
        VLOG_ERR_RL(&rl, "BUG: free_slot underflow: top=%d, slot=%d",
                    netdev_info->free_slot_top, slot);
        return;
    }

    top_slot = netdev_info->free_slots[netdev_info->free_slot_top];
    if (top_slot != slot) {
        VLOG_ERR_RL(&rl,
                    "BUG: inconsistent free_slot top: top_slot=%d, slot=%d",
                    top_slot, slot);
        return;
    }

    netdev_info->free_slot_top--;
}


#define FLOW_MASK_FIELD(MASK, FIELD) \
    memset(&(MASK).FIELD, 0xff, sizeof (MASK).FIELD)

static int
probe_supported_keys(struct netdev_info *netdev_info, struct btf *btf)
{
    struct miniflow *mf = &netdev_info->supported_keys;
    struct flowmap *map = &mf->map;
    struct flow mask;
    struct btf_member *m;
    const struct btf_type *t;
    int32_t flow_key_id;
    int i;

    flow_key_id = btf__find_by_name(btf, "xdp_flow");
    if (flow_key_id < 0) {
        VLOG_ERR("\"xdp_flow\" struct is not found in BTF");
        return EINVAL;
    }

    t = btf__type_by_id(btf, flow_key_id);
    if (!btf_is_struct(t)) {
        VLOG_ERR("\"xdp_flow\" is not struct");
        return EINVAL;
    }

    memset(&mask, 0, sizeof mask);
    flowmap_init(map);
    for (i = 0, m = btf_members(t); i < btf_vlen(t); i++, m++) {
        const char *name = btf__name_by_offset(btf, m->name_off);

        if (!strcmp(name, "dl_dst")) {
            FLOWMAP_SET(map, dl_dst);
            FLOW_MASK_FIELD(mask, dl_dst);
        } else if (!strcmp(name, "dl_src")) {
            FLOWMAP_SET(map, dl_src);
            FLOW_MASK_FIELD(mask, dl_src);
        } else if (!strcmp(name, "dl_type")) {
            FLOWMAP_SET(map, dl_type);
            FLOW_MASK_FIELD(mask, dl_type);
        } else if (!strcmp(name, "vlans")) {
            const struct btf_type *vt;
            const struct btf_array *arr;

            FLOWMAP_SET(map, vlans);
            vt = btf__type_by_id(btf, m->type);
            if (!btf_is_array(vt)) {
                VLOG_ERR("\"vlans\" field is not array");
                return EINVAL;
            }
            arr = btf_array(vt);
            if (arr->nelems > 2) {
                VLOG_ERR("\"vlans\" elems too many: %u", arr->nelems);
                return EINVAL;
            }
            memset(&mask.vlans, 0xff, sizeof mask.vlans[0] * arr->nelems);
        } else if (!strcmp(name, "nw_src")) {
            FLOWMAP_SET(map, nw_src);
            FLOW_MASK_FIELD(mask, nw_src);
        } else if (!strcmp(name, "nw_dst")) {
            FLOWMAP_SET(map, nw_dst);
            FLOW_MASK_FIELD(mask, nw_dst);
        } else if (!strcmp(name, "nw_frag")) {
            FLOWMAP_SET(map, nw_frag);
            FLOW_MASK_FIELD(mask, nw_frag);
        } else if (!strcmp(name, "nw_tos")) {
            FLOWMAP_SET(map, nw_tos);
            FLOW_MASK_FIELD(mask, nw_tos);
        } else if (!strcmp(name, "nw_ttl")) {
            FLOWMAP_SET(map, nw_ttl);
            FLOW_MASK_FIELD(mask, nw_ttl);
        } else if (!strcmp(name, "nw_proto")) {
            FLOWMAP_SET(map, nw_proto);
            FLOW_MASK_FIELD(mask, nw_proto);
        } else if (!strcmp(name, "tp_src")) {
            FLOWMAP_SET(map, tp_src);
            FLOW_MASK_FIELD(mask, tp_src);
        } else if (!strcmp(name, "tp_dst")) {
            FLOWMAP_SET(map, tp_dst);
            FLOW_MASK_FIELD(mask, tp_dst);
        } else if (strncmp(name, "pad", 3)) {
            VLOG_ERR("Unsupported flow key %s", name);
            return EOPNOTSUPP;
        }
    }

    miniflow_init(mf, &mask);

    return 0;
}

static bool
is_supported_keys(struct netdev_info *netdev_info, const struct minimask *mask)
{
    const struct miniflow *mf = &mask->masks;
    const uint64_t *p = miniflow_get_values(mf);
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX(idx, mf->map) {
        uint64_t supported = miniflow_get(&netdev_info->supported_keys, idx);
        if (~supported & *p) {
            VLOG_DBG("Unsupported key: Index=%lu, Supported=%lx, Mask=%lx",
                     idx, supported, *p);
            return false;
        }
        p++;
    }
    return true;
}

static int
probe_supported_actions(struct netdev_info *netdev_info, struct btf *btf)
{
    const struct btf_type *t;
    const struct btf_enum *v;
    int32_t supported_actions_id;
    int i;

    supported_actions_id = btf__find_by_name(btf, "action_attrs");
    if (supported_actions_id < 0) {
        VLOG_ERR("\"action_attrs\" enum not found in BTF");
        return EINVAL;
    }

    t = btf__type_by_id(btf, supported_actions_id);
    if (!btf_is_enum(t)) {
        VLOG_ERR("\"action_attrs\" is not enum");
        return EINVAL;
    }

    netdev_info->supported_actions = 0;
    v = btf_enum(t);
    for (i = 0; i < btf_vlen(t); i++) {
        const char *name = btf__name_by_offset(btf, v[i].name_off);

        switch (v[i].val) {
        case OVS_ACTION_ATTR_OUTPUT:
        case OVS_ACTION_ATTR_PUSH_VLAN:
        case OVS_ACTION_ATTR_POP_VLAN:
            netdev_info->supported_actions |= (1 << v[i].val);
            break;
        default:
            VLOG_ERR("Action \"%s\" (%d) is not supported",
                        name, v[i].val);
            return EOPNOTSUPP;
        }
    }

    return 0;
}

static bool
is_supported_actions(struct netdev_info *netdev_info,
                     const struct nlattr *actions, size_t actions_len)
{
    const struct nlattr *a;
    unsigned int left;

    NL_ATTR_FOR_EACH_UNSAFE(a, left, actions, actions_len) {
        int type = nl_attr_type(a);

        if (!(netdev_info->supported_actions & (1 << type))) {
            VLOG_DBG("Unsupported action: %d", type);
            return false;
        }
    }
    return true;
}


static struct netdev_info *
find_netdev_info(odp_port_t port)
{
    size_t port_hash = hash_bytes(&port, sizeof port, 0);
    struct netdev_info *netdev_info;

    HMAP_FOR_EACH_WITH_HASH(netdev_info, port_node, port_hash,
                            &netdev_info_table) {
        if (port == netdev_info->port) {
            return netdev_info;
        }
    }

    return NULL;
}

static int
get_odp_port(struct netdev *netdev, odp_port_t *port)
{
    int ifindex;

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_ERR_RL(&rl, "Failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    *port = netdev_ifindex_to_odp_port(ifindex);
    return 0;
}

static struct netdev_info *
get_netdev_info(struct netdev *netdev)
{
    struct netdev_info *netdev_info;
    odp_port_t port;

    if (get_odp_port(netdev, &port)) {
        return NULL;
    }

    netdev_info = find_netdev_info(port);
    if (!netdev_info) {
        VLOG_ERR_RL(&rl, "Failed to find netdev_info for %s",
                    netdev_get_name(netdev));
    }

    return netdev_info;
}


/* Convert odp_port to devmap_idx in output action */
static int
convert_port_to_devmap_idx(struct nlattr *actions, size_t actions_len)
{
    struct nlattr *a;
    unsigned int left;
    bool output_seen = false;

    NL_ATTR_FOR_EACH_UNSAFE(a, left, actions, actions_len) {
        int type = nl_attr_type(a);

        if (output_seen) {
            VLOG_DBG("XDP does not support packet copy");
            return EOPNOTSUPP;
        }

        if (type == OVS_ACTION_ATTR_OUTPUT) {
            odp_port_t *port;
            struct netdev_info *netdev_info;

            port = CONST_CAST(odp_port_t *,
                              nl_attr_get_unspec(a, sizeof(odp_port_t)));
            netdev_info = find_netdev_info(*port);
            if (!netdev_info) {
                VLOG_DBG("Cannot output to port %u without XDP prog attached",
                         *port);
                return EOPNOTSUPP;
            }
            /* XXX: Some NICs cannot handle XDP_REDIRECT'ed packets even with
             * XDP program enabled. Linux netdev community is considering
             * adding feature detection in XDP */

            *port = u32_to_odp(netdev_info->devmap_idx);
            output_seen = true;
        }
    }

    return 0;
}

static struct devmap_idx_data *
find_devmap_idx(int devmap_idx)
{
    struct devmap_idx_data *data;
    size_t hash = hash_bytes(&devmap_idx, sizeof devmap_idx, 0);

    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &devmap_idx_table) {
        if (devmap_idx == data->devmap_idx) {
            return data;
        }
    }

    return NULL;
}

static int
get_new_devmap_idx(int *pidx)
{
    static int max_devmap_idx = 0;
    int offset;

    for (offset = 0; offset < XDP_MAX_PORTS; offset++) {
        int devmap_idx = max_devmap_idx++;

        if (max_devmap_idx >= XDP_MAX_PORTS) {
            max_devmap_idx -= XDP_MAX_PORTS;
        }

        if (!find_devmap_idx(devmap_idx)) {
            struct devmap_idx_data *data;
            size_t hash = hash_bytes(&devmap_idx, sizeof devmap_idx, 0);

            data = xzalloc(sizeof *data);
            data->devmap_idx = devmap_idx;
            hmap_insert(&devmap_idx_table, &data->node, hash);

            *pidx = devmap_idx;
            return 0;
        }
    }

    return ENOSPC;
}

static void
delete_devmap_idx(int devmap_idx)
{
    struct devmap_idx_data *data = find_devmap_idx(devmap_idx);

    if (data) {
        hmap_remove(&devmap_idx_table, &data->node);
        free(data);
    }
}


static int
get_table_fd(const struct bpf_object *obj, const char *table_name,
             int *pmap_fd)
{
    struct bpf_map *map;
    int map_fd;

    map = bpf_object__find_map_by_name(obj, table_name);
    if (!map) {
        VLOG_ERR_RL(&rl, "BPF map \"%s\" not found", table_name);
        return ENOENT;
    }

    map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        VLOG_ERR_RL(&rl, "Invalid BPF map fd: %s",
                    ovs_libbpf_strerror(map_fd));
        return EINVAL;
    }

    *pmap_fd = map_fd;
    return 0;
}

static int
get_subtbl_masks_hd_fd(const struct bpf_object *obj, int *head_fd)
{
    return get_table_fd(obj, "subtbl_masks_hd", head_fd);
}

static int
get_subtbl_masks_hd(int head_fd, int *head)
{
    int err, zero = 0;

    if (bpf_map_lookup_elem(head_fd, &zero, head)) {
        err = errno;
        VLOG_ERR_RL(&rl, "Cannot get subtbl_masks_hd: %s",
                    ovs_strerror(errno));
        return err;
    }

    return 0;
}

static int
update_subtbl_masks_hd(int head_fd, int head)
{
    int err, zero = 0;

    if (bpf_map_update_elem(head_fd, &zero, &head, 0)) {
        err = errno;
        VLOG_ERR_RL(&rl, "Cannot update subtbl_masks_hd: %s",
                    ovs_strerror(errno));
        return err;
    }

    return 0;
}

static int
get_subtbl_masks_fd(const struct bpf_object *obj, int *masks_fd)
{
    return get_table_fd(obj, "subtbl_masks", masks_fd);
}

static int
get_flow_table_fd(const struct bpf_object *obj, int *tables_fd)
{
    return get_table_fd(obj, "flow_table", tables_fd);
}

static int
get_output_map_fd(const struct bpf_object *obj, int *output_map_fd)
{
    return get_table_fd(obj, "output_map", output_map_fd);
}


static int
netdev_xdp_flow_put(struct netdev *netdev, struct match *match_,
                    struct nlattr *actions, size_t actions_len,
                    const ovs_u128 *ufid, struct offload_info *info OVS_UNUSED,
                    struct dpif_flow_stats *stats OVS_UNUSED)
{
    struct netdev_info *netdev_info;
    struct bpf_object *obj = get_xdp_object(netdev);
    struct minimatch minimatch;
    struct match *match;
    uint32_t key_size;
    size_t fidx;
    uint64_t *flow_u64, *mask_u64, *tmp_values;
    int masks_fd, head_fd, flow_table_fd, subtbl_fd, free_slot, head;
    struct xdp_subtable_mask_header *entry, *pentry;
    struct xdp_flow_actions_header *xdp_actions;
    char subtbl_name[BPF_OBJ_NAME_LEN];
    size_t hash;
    struct ufid_to_xdp_data *data;
    int cnt, idx, pidx;
    int err;

    netdev_info = get_netdev_info(netdev);
    if (!netdev_info) {
        return ENOENT;
    }

    /* Assume only eth packets on packet reception in XDP */
    if (match_->wc.masks.packet_type &&
        match_->flow.packet_type != htonl(PT_ETH)) {
        VLOG_DBG_RL(&rl, "Packet type not ETH");
        return EOPNOTSUPP;
    }

    /* probe_supported_key() does not support recirculation */
    if (match_->wc.masks.recirc_id && match_->flow.recirc_id) {
        VLOG_DBG_RL(&rl, "Recirc id not zero");
        return EOPNOTSUPP;
    }

    match = xmemdup(match_, sizeof *match);
    /* XDP only handles packets with packet_type = 0 and recirc_id = 0 so
     * clear masks to reduce max key size */
    match->wc.masks.packet_type = 0;
    match->wc.masks.recirc_id = 0;
    /* We install per-port XDP classifier table so no need for odp_port */
    match->wc.masks.in_port.odp_port = 0;
    minimatch_init(&minimatch, match);
    free(match);

    key_size = MINIFLOW_VALUES_SIZE(miniflow_n_values(minimatch.flow));
    if (key_size > netdev_info->key_size) {
        err = EOPNOTSUPP;
        VLOG_DBG_RL(&rl, "Key size too big");
        goto err;
    }

    if (sizeof(struct xdp_flow_actions_header) + actions_len >
        netdev_info->max_actions_len) {
        err = EOPNOTSUPP;
        VLOG_DBG_RL(&rl, "Actions size too big");
        goto err;
    }

    /* XDP only uses masked keys so need to mask the key before adding an
     * entry otherwise table miss unexpectedly happens in XDP */
    mask_u64 = miniflow_values(&minimatch.mask->masks);
    flow_u64 = miniflow_values(minimatch.flow);
    FLOWMAP_FOR_EACH_INDEX(fidx, minimatch.mask->masks.map) {
        *flow_u64++ &= *mask_u64++;
    }

    if (!is_supported_keys(netdev_info, minimatch.mask)) {
        err = EOPNOTSUPP;
        VLOG_DBG_RL(&rl, "Key not supported");
        goto err;
    }

    if (!is_supported_actions(netdev_info, actions, actions_len)) {
        err = EOPNOTSUPP;
        VLOG_DBG_RL(&rl, "Actions not supported");
        goto err;
    }

    /* subtables in XDP is hash table whose key is miniflow value and whose
     * value is actions preceded by actions_len */
    xdp_actions = xzalloc(netdev_info->max_actions_len);
    xdp_actions->actions_len = actions_len;
    memcpy(xdp_flow_actions(xdp_actions), actions, actions_len);

    /* TODO: Use XDP_TX for redirect action when possible */
    err = convert_port_to_devmap_idx(xdp_flow_actions(xdp_actions),
                                     actions_len);
    if (err) {
        goto err_actions;
    }

    err = get_subtbl_masks_fd(obj, &masks_fd);
    if (err) {
        goto err_actions;
    }

    err = get_subtbl_masks_hd_fd(obj, &head_fd);
    if (err) {
        goto err_actions;
    }

    err = get_subtbl_masks_hd(head_fd, &head);
    if (err) {
        goto err_actions;
    }

    err = get_flow_table_fd(obj, &flow_table_fd);
    if (err) {
        goto err_actions;
    }

    entry = xzalloc(netdev_info->subtable_mask_size);
    pentry = xzalloc(netdev_info->subtable_mask_size);

    /* Iterate subtable mask list implemented using array */
    idx = head;
    for (cnt = 0; cnt < netdev_info->max_subtables; cnt++) {
        if (idx == XDP_SUBTABLES_TAIL) {
            break;
        }

        if (bpf_map_lookup_elem(masks_fd, &idx, entry)) {
            err = errno;
            VLOG_ERR_RL(&rl, "Cannot lookup subtbl_masks: %s",
                        ovs_strerror(errno));
            goto err_entry;
        }

        if (minimask_equal(minimatch.mask, &entry->mask)) {
            __u32 id;

            if (bpf_map_lookup_elem(flow_table_fd, &idx, &id)) {
                err = errno;
                VLOG_ERR_RL(&rl, "Cannot lookup flow_table: %s",
                            ovs_strerror(errno));
                goto err_entry;
            }

            subtbl_fd = bpf_map_get_fd_by_id(id);
            if (subtbl_fd < 0) {
                err = errno;
                VLOG_ERR_RL(&rl, "Cannot get subtbl fd by id: %s",
                            ovs_strerror(errno));
                goto err_entry;
            }

            tmp_values = xzalloc(netdev_info->key_size);
            memcpy(tmp_values, miniflow_get_values(minimatch.flow), key_size);
            if (bpf_map_update_elem(subtbl_fd, tmp_values, xdp_actions, 0)) {
                err = errno;
                VLOG_ERR_RL(&rl, "Cannot insert flow entry: %s",
                            ovs_strerror(errno));
                free(tmp_values);
                goto err_close;
            }

            entry->count++;
            if (bpf_map_update_elem(masks_fd, &idx, entry, 0)) {
                err = errno;
                VLOG_ERR_RL(&rl, "Cannot update subtbl_masks count: %s",
                            ovs_strerror(errno));
                bpf_map_delete_elem(subtbl_fd, tmp_values);
                free(tmp_values);
                goto err_close;
            }
            free(tmp_values);

            goto out;
        }

        memcpy(pentry, entry, netdev_info->subtable_mask_size);
        pidx = idx;
        idx = entry->next;
    }

    if (cnt == netdev_info->max_subtables && idx != XDP_SUBTABLES_TAIL) {
        err = EINVAL;
        VLOG_ERR_RL(&rl,
                    "Cannot lookup subtbl_masks: Broken subtbl_masks list");
        goto err_entry;
    }

    /* Subtable was not found. Create a new one */

    err = get_subtbl_masks_free_slot(netdev_info, &free_slot);
    if (err) {
        goto err_entry;
    }

    miniflow_clone(&entry->mask.masks, &minimatch.mask->masks,
                   miniflow_n_values(&minimatch.mask->masks));
    entry->mf_bits_u0 = count_1bits(minimatch.mask->masks.map.bits[0]);
    entry->mf_bits_u1 = count_1bits(minimatch.mask->masks.map.bits[1]);
    entry->count = 1;
    entry->next = XDP_SUBTABLES_TAIL;
    if (bpf_map_update_elem(masks_fd, &free_slot, entry, 0)) {
        err = errno;
        VLOG_ERR_RL(&rl, "Cannot update subtbl_masks: %s",
                    ovs_strerror(errno));
        goto err_entry;
    }

    if (snprintf(subtbl_name, BPF_OBJ_NAME_LEN, "subtbl_%d_%d",
                 netdev_info->port, free_slot) < 0) {
        err = errno;
        VLOG_ERR_RL(&rl, "snprintf for subtable name failed: %s",
                    ovs_strerror(errno));
        goto err_entry;
    }
    subtbl_fd = bpf_create_map_name(BPF_MAP_TYPE_HASH, subtbl_name,
                                    netdev_info->key_size,
                                    netdev_info->max_actions_len,
                                    netdev_info->max_entries, 0);
    if (subtbl_fd < 0) {
        err = errno;
        VLOG_ERR_RL(&rl, "map creation for subtbl failed: %s",
                    ovs_strerror(errno));
        goto err_entry;
    }

    tmp_values = xzalloc(netdev_info->key_size);
    memcpy(tmp_values, miniflow_get_values(minimatch.flow), key_size);
    if (bpf_map_update_elem(subtbl_fd, tmp_values, xdp_actions, 0)) {
        err = errno;
        VLOG_ERR_RL(&rl, "Cannot insert flow entry: %s", ovs_strerror(errno));
        free(tmp_values);
        goto err_close;
    }
    free(tmp_values);

    if (bpf_map_update_elem(flow_table_fd, &free_slot, &subtbl_fd, 0)) {
        err = errno;
        VLOG_ERR_RL(&rl, "Failed to insert subtbl into flow_table: %s",
                    ovs_strerror(errno));
        goto err_close;
    }

    if (cnt == 0) {
        err = update_subtbl_masks_hd(head_fd, free_slot);
        if (err) {
            goto err_subtbl;
        }
    } else {
        pentry->next = free_slot;
        /* This effectively only updates one byte of entry->next */
        if (bpf_map_update_elem(masks_fd, &pidx, pentry, 0)) {
            err = errno;
            VLOG_ERR_RL(&rl, "Cannot update subtbl_masks prev entry: %s",
                        ovs_strerror(errno));
            goto err_subtbl;
        }
    }
    delete_subtbl_masks_free_slot(netdev_info, free_slot);
out:
    hash = hash_bytes(ufid, sizeof *ufid, 0);
    data = xzalloc(sizeof *data);
    data->ufid = *ufid;
    miniflow_clone(&data->mask.masks, &minimatch.mask->masks,
                   miniflow_n_values(&minimatch.mask->masks));
    miniflow_clone(&data->flow, minimatch.flow,
                   miniflow_n_values(minimatch.flow));
    ovs_mutex_lock(&ufid_lock);
    hmap_insert(&ufid_to_xdp, &data->ufid_node, hash);
    ovs_mutex_unlock(&ufid_lock);
err_close:
    close(subtbl_fd);
err_entry:
    free(pentry);
    free(entry);
err_actions:
    free(xdp_actions);
err:
    minimatch_destroy(&minimatch);

    return err;

err_subtbl:
    bpf_map_delete_elem(flow_table_fd, &free_slot);

    goto err_close;
}

static int
netdev_xdp_flow_get(struct netdev *netdev OVS_UNUSED,
                    struct match *match OVS_UNUSED,
                    struct nlattr **actions OVS_UNUSED,
                    const ovs_u128 *ufid OVS_UNUSED,
                    struct dpif_flow_stats *stats OVS_UNUSED,
                    struct dpif_flow_attrs *attrs OVS_UNUSED,
                    struct ofpbuf *buf OVS_UNUSED)
{
    /* FIXME: Implement this */
    return 0;
}

static int
netdev_xdp_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                    struct dpif_flow_stats *stats OVS_UNUSED)
{
    struct netdev_info *netdev_info;
    struct bpf_object *obj = get_xdp_object(netdev);
    size_t hash;
    struct ufid_to_xdp_data *data;
    int masks_fd, head_fd, flow_table_fd, subtbl_fd, head;
    struct xdp_subtable_mask_header *entry, *pentry;
    int err, cnt, idx, pidx;
    __u32 id;

    netdev_info = get_netdev_info(netdev);
    if (!netdev_info) {
        return ENOENT;
    }

    err = get_subtbl_masks_fd(obj, &masks_fd);
    if (err) {
        return err;
    }

    err = get_subtbl_masks_hd_fd(obj, &head_fd);
    if (err) {
        return err;
    }

    err = get_subtbl_masks_hd(head_fd, &head);
    if (err) {
        return err;
    }

    err = get_flow_table_fd(obj, &flow_table_fd);
    if (err) {
        return err;
    }

    hash = hash_bytes(ufid, sizeof *ufid, 0);
    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH(data, ufid_node, hash, &ufid_to_xdp) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            break;
        }
    }
    if (!data) {
        ovs_mutex_unlock(&ufid_lock);
        VLOG_WARN_RL(&rl, "Cannot find flow key to delete");
        return ENOENT;
    }
    hmap_remove(&ufid_to_xdp, &data->ufid_node);
    ovs_mutex_unlock(&ufid_lock);

    entry = xzalloc(netdev_info->subtable_mask_size);
    pentry = xzalloc(netdev_info->subtable_mask_size);

    /* Iterate subtable mask list implemented using array */
    idx = head;
    for (cnt = 0; cnt < netdev_info->max_subtables; cnt++) {
        if (idx == XDP_SUBTABLES_TAIL) {
            err = ENOENT;
            VLOG_ERR_RL(&rl, "Cannot lookup subtbl_masks: %s",
                        ovs_strerror(err));
            goto out;
        }

        if (bpf_map_lookup_elem(masks_fd, &idx, entry)) {
            err = errno;
            VLOG_ERR_RL(&rl, "Cannot lookup subtbl_masks: %s",
                        ovs_strerror(errno));
            goto out;
        }

        if (minimask_equal(&data->mask, &entry->mask)) {
            break;
        }

        memcpy(pentry, entry, netdev_info->subtable_mask_size);
        pidx = idx;
        idx = entry->next;
    }

    if (cnt == netdev_info->max_subtables) {
        err = ENOENT;
        VLOG_ERR_RL(&rl,
                    "Cannot lookup subtbl_masks: Broken subtbl_masks list");
        goto out;
    }

    if (bpf_map_lookup_elem(flow_table_fd, &idx, &id)) {
        err = errno;
        VLOG_ERR_RL(&rl, "Cannot lookup flow_table: %s", ovs_strerror(errno));
        goto out;
    }

    subtbl_fd = bpf_map_get_fd_by_id(id);
    if (subtbl_fd < 0) {
        err = errno;
        VLOG_ERR_RL(&rl, "Cannot get subtbl fd by id: %s",
                    ovs_strerror(errno));
        goto out;
    }

    bpf_map_delete_elem(subtbl_fd, miniflow_get_values(&data->flow));
    close(subtbl_fd);

    if (--entry->count > 0) {
        if (bpf_map_update_elem(masks_fd, &idx, entry, 0)) {
            err = errno;
            VLOG_ERR_RL(&rl, "Cannot update subtbl_masks count: %s",
                        ovs_strerror(errno));
        }

        goto out;
    }

    if (entry->count == (uint16_t)-1) {
        VLOG_WARN_RL(&rl, "subtbl_masks has negative count: %d",
                     entry->count);
    }

    if (cnt == 0) {
        err = update_subtbl_masks_hd(head_fd, entry->next);
        if (err) {
            goto out;
        }
    } else {
        pentry->next = entry->next;
        /* This effectively only updates one byte of entry->next */
        if (bpf_map_update_elem(masks_fd, &pidx, pentry, 0)) {
            err = errno;
            VLOG_ERR_RL(&rl, "Cannot update subtbl_masks prev entry: %s",
                        ovs_strerror(errno));
            goto out;
        }
    }

    bpf_map_delete_elem(flow_table_fd, &idx);
    err = add_subtbl_masks_free_slot(netdev_info, idx);
    if (err) {
        VLOG_ERR_RL(&rl, "Cannot add subtbl_masks free slot: %s",
                    ovs_strerror(err));
    }
out:
    free(data);
    free(pentry);
    free(entry);

    return err;
}

static int
netdev_xdp_init_flow_api(struct netdev *netdev)
{
    struct bpf_object *obj;
    struct btf *btf;
    struct netdev_info *netdev_info;
    struct bpf_map *flow_table, *subtbl_template, *subtbl_masks;
    const struct bpf_map_def *flow_table_def, *subtbl_def, *subtbl_masks_def;
    odp_port_t port;
    size_t port_hash;
    int output_map_fd;
    int err, ifindex, devmap_idx;

    if (!has_xdp_flowtable(netdev)) {
        return EOPNOTSUPP;
    }

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_ERR("Failed to get ifindex for %s: %s",
                 netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }
    port = netdev_ifindex_to_odp_port(ifindex);

    netdev_info = find_netdev_info(port);
    if (netdev_info) {
        VLOG_ERR("xdp offload is already initialized for netdev %s",
                 netdev_get_name(netdev));
        return EEXIST;
    }

    obj = get_xdp_object(netdev);
    btf = bpf_object__btf(obj);
    if (!btf) {
        VLOG_ERR("BPF object for netdev \"%s\" does not contain BTF",
                 netdev_get_name(netdev));
        return EINVAL;
    }

    err = get_new_devmap_idx(&devmap_idx);
    if (err) {
        VLOG_ERR("Failed to get new devmap idx: %s", ovs_strerror(err));
        return err;
    }

    netdev_info = xzalloc(sizeof *netdev_info);
    netdev_info->devmap_idx = devmap_idx;

    if (get_odp_port(netdev, &netdev_info->port) || !netdev_info->port) {
        VLOG_ERR("Failed to get odp_port for %s", netdev_get_name(netdev));
        err = ENOENT;
        goto err;
    }

    err = probe_supported_keys(netdev_info, btf);
    if (err) {
        VLOG_ERR("Failed to initialize supported_keys for %s",
                 netdev_get_name(netdev));
        goto err;
    }
    err = probe_supported_actions(netdev_info, btf);
    if (err) {
        VLOG_ERR("Failed to initialize supported_actions for %s",
                 netdev_get_name(netdev));
        goto err;
    }

    flow_table = bpf_object__find_map_by_name(obj, "flow_table");
    if (!flow_table) {
        VLOG_ERR("BPF map \"flow_table\" not found");
        err = ENOENT;
        goto err;
    }
    flow_table_def = bpf_map__def(flow_table);
    if (flow_table_def->max_entries > XDP_MAX_SUBTABLES) {
        VLOG_ERR("flow_table max_entries must not be greater than %d",
                 XDP_MAX_SUBTABLES);
        goto err;
    }
    netdev_info->max_subtables = flow_table_def->max_entries;

    subtbl_template = bpf_object__find_map_by_name(obj, "subtbl_template");
    if (!subtbl_template) {
        VLOG_ERR("BPF map \"subtbl_template\" not found");
        err = ENOENT;
        goto err;
    }
    subtbl_def = bpf_map__def(subtbl_template);
    netdev_info->key_size = subtbl_def->key_size;
    netdev_info->max_actions_len = subtbl_def->value_size;
    netdev_info->max_entries = subtbl_def->max_entries;

    subtbl_masks = bpf_object__find_map_by_name(obj, "subtbl_masks");
    if (!subtbl_masks) {
        VLOG_ERR("BPF map \"subtbl_masks\" not found");
        err = ENOENT;
        goto err;
    }
    subtbl_masks_def = bpf_map__def(subtbl_masks);
    if (subtbl_masks_def->max_entries != netdev_info->max_subtables) {
        VLOG_ERR("\"subtbl_masks\" map has different max_entries from \"flow_table\"");
        goto err;
    }
    netdev_info->subtable_mask_size = subtbl_masks_def->value_size;
    init_subtbl_masks_free_slot(netdev_info);

    err = get_output_map_fd(obj, &output_map_fd);
    if (err) {
        goto err;
    }
    if (bpf_map_update_elem(output_map_fd, &devmap_idx, &ifindex, 0)) {
        err = errno;
        VLOG_ERR("Failed to insert idx %d if %s into output_map: %s",
                 devmap_idx, netdev_get_name(netdev), ovs_strerror(errno));
        goto err;
    }

    port_hash = hash_bytes(&port, sizeof port, 0);
    hmap_insert(&netdev_info_table, &netdev_info->port_node, port_hash);

    return 0;
err:
    free(netdev_info);
    delete_devmap_idx(devmap_idx);
    return err;
}

static void
netdev_xdp_uninit_flow_api(struct netdev *netdev)
{
    struct bpf_object *obj;
    struct netdev_info *netdev_info;
    int output_map_fd, devmap_idx;

    netdev_info = get_netdev_info(netdev);
    if (!netdev_info) {
        VLOG_WARN("%s: netdev_info not found on uninitializing xdp flow api",
                  netdev_get_name(netdev));
        return;
    }
    hmap_remove(&netdev_info_table, &netdev_info->port_node);

    devmap_idx = netdev_info->devmap_idx;
    obj = get_xdp_object(netdev);
    if (!get_output_map_fd(obj, &output_map_fd)) {
        bpf_map_delete_elem(output_map_fd, &devmap_idx);
    } else {
        VLOG_WARN("%s: Failed to get output_map fd on uninitializing xdp flow api",
                  netdev_get_name(netdev));
    }

    free(netdev_info);
    delete_devmap_idx(devmap_idx);
}

const struct netdev_flow_api netdev_offload_xdp = {
    .type = "linux_xdp",
    .flow_put = netdev_xdp_flow_put,
    .flow_get = netdev_xdp_flow_get,
    .flow_del = netdev_xdp_flow_del,
    .init_flow_api = netdev_xdp_init_flow_api,
    .uninit_flow_api = netdev_xdp_uninit_flow_api,
};
