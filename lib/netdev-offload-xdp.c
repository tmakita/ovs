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
#include "id-pool.h"
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

static struct hmap netdev_xdp_info_table =
    HMAP_INITIALIZER(&netdev_xdp_info_table);

struct netdev_xdp_info {
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
    uint32_t max_actions;
    uint32_t max_actions_len;
    uint32_t max_entries;
    struct id_pool *free_slots;
};

static struct id_pool *devmap_idx_pool;

struct devmap_idx_data {
    struct hmap_node node;
    int devmap_idx;
};


#define FLOW_MASK_FIELD(MASK, FIELD) \
    memset(&(MASK).FIELD, 0xff, sizeof (MASK).FIELD)

static int
probe_supported_keys(struct netdev_xdp_info *netdev_xdp_info, struct btf *btf,
                     uint32_t type)
{
    struct miniflow *mf = &netdev_xdp_info->supported_keys;
    struct flowmap *map = &mf->map;
    struct flow mask;
    struct btf_member *m;
    const struct btf_type *pt, *t;
    int i;

    pt = btf__type_by_id(btf, type);
    if (!pt) {
        VLOG_ERR("\"supported_keys\" field type is unknown");
        return EINVAL;
    }
    if (!btf_is_ptr(pt)) {
        VLOG_ERR("\"supported_keys\" field is not ptr");
        return EINVAL;
    }
    t = btf__type_by_id(btf, pt->type);
    if (!t) {
        VLOG_ERR("\"supported_keys\" ptr type is unknown");
        return EINVAL;
    }
    if (!btf_is_struct(t)) {
        VLOG_ERR("\"supported_keys\" field is not struct ptr");
        return EINVAL;
    }

    memset(&mask, 0, sizeof mask);
    flowmap_init(map);
    for (i = 0, m = btf_members(t); i < btf_vlen(t); i++, m++) {
        const char *name = btf__name_by_offset(btf, m->name_off);

        if (!name) {
            VLOG_ERR("Unnamed field #%d in \"supported_keys\" struct", i);
            return EINVAL;
        }
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
            if (!vt) {
                VLOG_ERR("\"vlans\" field type is unknown");
                return EINVAL;
            }
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
is_supported_keys(struct netdev_xdp_info *netdev_xdp_info,
                  const struct minimask *mask)
{
    const struct miniflow *mf = &mask->masks;
    const uint64_t *p = miniflow_get_values(mf);
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX (idx, mf->map) {
        uint64_t supported = miniflow_get(&netdev_xdp_info->supported_keys,
                                          idx);
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
probe_supported_actions(struct netdev_xdp_info *netdev_xdp_info,
                        struct btf *btf, uint32_t type)
{
    const struct btf_type *pt, *t;
    const struct btf_enum *v;
    int i;

    pt = btf__type_by_id(btf, type);
    if (!pt) {
        VLOG_ERR("\"supported_actions\" field type is unknown");
        return EINVAL;
    }
    if (!btf_is_ptr(pt)) {
        VLOG_ERR("\"supported_actions\" field is not ptr");
        return EINVAL;
    }
    t = btf__type_by_id(btf, pt->type);
    if (!t) {
        VLOG_ERR("\"supported_actions\" ptr type is unknown");
        return EINVAL;
    }
    if (!btf_is_enum(t)) {
        VLOG_ERR("\"supported_actions\" field is not enum ptr");
        return EINVAL;
    }

    netdev_xdp_info->supported_actions = 0;
    v = btf_enum(t);
    for (i = 0; i < btf_vlen(t); i++) {
        const char *name = btf__name_by_offset(btf, v[i].name_off);

        if (!name) {
            VLOG_ERR("Unnamed field #%d in \"supported_actions\" enum", i);
            return EINVAL;
        }
        switch (v[i].val) {
        case OVS_ACTION_ATTR_OUTPUT:
        case OVS_ACTION_ATTR_PUSH_VLAN:
        case OVS_ACTION_ATTR_POP_VLAN:
            netdev_xdp_info->supported_actions |= (1 << v[i].val);
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
is_supported_actions(struct netdev_xdp_info *netdev_xdp_info,
                     const struct nlattr *actions, size_t actions_len)
{
    const struct nlattr *a;
    unsigned int left;
    int actions_num = 0;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);

        if (!(netdev_xdp_info->supported_actions & (1 << type))) {
            VLOG_DBG("Unsupported action: %d", type);
            return false;
        }
        actions_num++;
    }

    if (actions_num > netdev_xdp_info->max_actions) {
        VLOG_DBG("Too many actions: %d", actions_num);
        return false;
    }
    return true;
}

static int
probe_max_actions(struct netdev_xdp_info *netdev_xdp_info, struct btf *btf,
                  uint32_t type)
{
    const struct btf_type *pt, *at;
    const struct btf_array *arr;

    pt = btf__type_by_id(btf, type);
    if (!pt) {
        VLOG_ERR("\"max_actions\" field type is unknown");
        return EINVAL;
    }
    if (!btf_is_ptr(pt)) {
        VLOG_ERR("\"max_actions\" field is not ptr");
        return EINVAL;
    }
    at = btf__type_by_id(btf, pt->type);
    if (!at) {
        VLOG_ERR("\"max_actions\" ptr type is unknown");
        return EINVAL;
    }
    if (!btf_is_array(at)) {
        VLOG_ERR("\"max_actions\" field is not array ptr");
        return EINVAL;
    }
    arr = btf_array(at);
    netdev_xdp_info->max_actions = arr->nelems;

    return 0;
}

static int
probe_meta_info(struct netdev_xdp_info *netdev_xdp_info, struct btf *btf)
{
    int32_t meta_sec_id;
    struct btf_var_secinfo *vi;
    struct btf_member *m;
    const struct btf_type *sec, *t = NULL;
    bool supported_keys_found = false;
    int i;

    meta_sec_id = btf__find_by_name_kind(btf, ".ovs_meta", BTF_KIND_DATASEC);
    if (meta_sec_id < 0) {
        VLOG_ERR("BUG: \".ovs_meta\" datasec not found in BTF");
        return EINVAL;
    }

    sec = btf__type_by_id(btf, meta_sec_id);
    for (i = 0, vi = btf_var_secinfos(sec); i < btf_vlen(sec); i++, vi++) {
        const struct btf_type *var = btf__type_by_id(btf, vi->type);
        const char *name;

        if (!var) {
            VLOG_ERR("\".ovs_meta\" var #%d type is unknown", i);
            return EINVAL;
        }
        name = btf__name_by_offset(btf, var->name_off);
        if (!name) {
            VLOG_ERR("\".ovs_meta\" var #%d name is empty", i);
            return EINVAL;
        }
        if (strcmp(name, "meta_info")) {
            continue;
        }
        if (!btf_is_var(var)) {
            VLOG_ERR("\"meta_info\" is not var");
            return EINVAL;
        }
        t = btf__type_by_id(btf, var->type);
        if (!t) {
            VLOG_ERR("\"meta_info\" var type is unknown");
            return EINVAL;
        }
        break;
    }

    if (!t) {
        VLOG_ERR("\"meta_info\" var not found in \".ovs_meta\" datasec");
        return EINVAL;
    }

    if (!btf_is_struct(t)) {
        VLOG_ERR("\"meta_info\" is not struct");
        return EINVAL;
    }

    for (i = 0, m = btf_members(t); i < btf_vlen(t); i++, m++) {
        const char *name = btf__name_by_offset(btf, m->name_off);
        int err;

        if (!name) {
            VLOG_ERR("Invalid field #%d in \"meta_info\" struct", i);
            return EINVAL;
        }
        if (!strcmp(name, "supported_keys")) {
            err = probe_supported_keys(netdev_xdp_info, btf, m->type);
            if (err) {
                return err;
            }
            supported_keys_found = true;
        } else if (!strcmp(name, "supported_actions")) {
            err = probe_supported_actions(netdev_xdp_info, btf, m->type);
            if (err) {
                return err;
            }
        } else if (!strcmp(name, "max_actions")) {
            err = probe_max_actions(netdev_xdp_info, btf, m->type);
            if (err) {
                return err;
            }
        } else {
            VLOG_ERR("Unsupported meta_info key %s", name);
            return EOPNOTSUPP;
        }
    }

    if (!supported_keys_found) {
        VLOG_ERR("\"supported_keys\" field not found in \"meta_info\"");
        return EINVAL;
    }
    if (!netdev_xdp_info->supported_actions) {
        VLOG_ERR("\"supported_actions\" field not found in \"meta_info\"");
        return EINVAL;
    }
    if (!netdev_xdp_info->max_actions) {
        VLOG_ERR("\"max_actions\" field not found in \"meta_info\"");
        return EINVAL;
    }

    return 0;
}


static struct netdev_xdp_info *
find_netdev_xdp_info(odp_port_t port)
{
    size_t port_hash = hash_bytes(&port, sizeof port, 0);
    struct netdev_xdp_info *netdev_xdp_info;

    HMAP_FOR_EACH_WITH_HASH (netdev_xdp_info, port_node, port_hash,
                             &netdev_xdp_info_table) {
        if (port == netdev_xdp_info->port) {
            return netdev_xdp_info;
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

static struct netdev_xdp_info *
get_netdev_xdp_info(struct netdev *netdev)
{
    struct netdev_xdp_info *netdev_xdp_info;
    odp_port_t port;

    if (get_odp_port(netdev, &port)) {
        return NULL;
    }

    netdev_xdp_info = find_netdev_xdp_info(port);
    if (!netdev_xdp_info) {
        VLOG_ERR_RL(&rl, "Failed to find netdev_xdp_info for %s",
                    netdev_get_name(netdev));
    }

    return netdev_xdp_info;
}

/* Convert odp_port to devmap_idx in output action */
static int
convert_port_to_devmap_idx(struct nlattr *actions, size_t actions_len)
{
    struct nlattr *a;
    unsigned int left;
    bool output_seen = false;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);

        if (output_seen) {
            VLOG_DBG("XDP does not support packet copy");
            return EOPNOTSUPP;
        }

        if (type == OVS_ACTION_ATTR_OUTPUT) {
            odp_port_t *port;
            struct netdev_xdp_info *netdev_xdp_info;

            port = CONST_CAST(odp_port_t *,
                              nl_attr_get_unspec(a, sizeof(odp_port_t)));
            netdev_xdp_info = find_netdev_xdp_info(*port);
            if (!netdev_xdp_info) {
                VLOG_DBG("Cannot output to port %u without XDP prog attached",
                         *port);
                return EOPNOTSUPP;
            }
            /* NOTE: Some NICs cannot handle XDP_REDIRECT'ed packets even with
             * XDP program enabled. Linux netdev community is considering
             * adding feature detection in XDP */

            *port = u32_to_odp(netdev_xdp_info->devmap_idx);
            output_seen = true;
        }
    }

    return 0;
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
                    const ovs_u128 *ufid,
                    struct offload_info *info OVS_UNUSED,
                    struct dpif_flow_stats *stats OVS_UNUSED)
{
    struct netdev_xdp_info *netdev_xdp_info;
    struct bpf_object *obj = get_xdp_object(netdev);
    struct minimatch minimatch;
    struct match *match;
    uint32_t key_size, free_slot;
    size_t fidx;
    uint64_t *flow_u64, *mask_u64, *tmp_values;
    int masks_fd, head_fd, flow_table_fd, subtbl_fd, head;
    struct xdp_subtable_mask_header *entry, *pentry;
    struct xdp_flow_actions_header *xdp_actions;
    char subtbl_name[BPF_OBJ_NAME_LEN];
    size_t hash;
    struct ufid_to_xdp_data *data;
    int cnt, idx, pidx;
    int err;

    netdev_xdp_info = get_netdev_xdp_info(netdev);
    if (!netdev_xdp_info) {
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
    if (key_size > netdev_xdp_info->key_size) {
        err = EOPNOTSUPP;
        VLOG_DBG_RL(&rl, "Key size too big");
        goto err;
    }

    if (sizeof(struct xdp_flow_actions_header) + actions_len >
        netdev_xdp_info->max_actions_len) {
        err = EOPNOTSUPP;
        VLOG_DBG_RL(&rl, "Actions size too big");
        goto err;
    }

    /* XDP only uses masked keys so need to mask the key before adding an
     * entry otherwise table miss unexpectedly happens in XDP */
    mask_u64 = miniflow_values(&minimatch.mask->masks);
    flow_u64 = miniflow_values(minimatch.flow);
    FLOWMAP_FOR_EACH_INDEX (fidx, minimatch.mask->masks.map) {
        *flow_u64++ &= *mask_u64++;
    }

    if (!is_supported_keys(netdev_xdp_info, minimatch.mask)) {
        err = EOPNOTSUPP;
        VLOG_DBG_RL(&rl, "Key not supported");
        goto err;
    }

    if (!is_supported_actions(netdev_xdp_info, actions, actions_len)) {
        err = EOPNOTSUPP;
        VLOG_DBG_RL(&rl, "Actions not supported");
        goto err;
    }

    /* subtables in XDP is hash table whose key is miniflow value and whose
     * value is actions preceded by actions_len */
    xdp_actions = xzalloc(netdev_xdp_info->max_actions_len);
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

    entry = xzalloc(netdev_xdp_info->subtable_mask_size);
    pentry = xzalloc(netdev_xdp_info->subtable_mask_size);

    /* Iterate subtable mask list implemented using array */
    idx = head;
    for (cnt = 0; cnt < netdev_xdp_info->max_subtables; cnt++) {
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

            tmp_values = xzalloc(netdev_xdp_info->key_size);
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

        memcpy(pentry, entry, netdev_xdp_info->subtable_mask_size);
        pidx = idx;
        idx = entry->next;
    }

    if (cnt == netdev_xdp_info->max_subtables && idx != XDP_SUBTABLES_TAIL) {
        err = EINVAL;
        VLOG_ERR_RL(&rl,
                    "Cannot lookup subtbl_masks: Broken subtbl_masks list");
        goto err_entry;
    }

    /* Subtable was not found. Create a new one */

    if (!id_pool_alloc_id(netdev_xdp_info->free_slots, &free_slot)) {
        err = ENOBUFS;
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
        goto err_slot;
    }

    if (snprintf(subtbl_name, BPF_OBJ_NAME_LEN, "subtbl_%d_%d",
                 netdev_xdp_info->port, free_slot) < 0) {
        err = errno;
        VLOG_ERR_RL(&rl, "snprintf for subtable name failed: %s",
                    ovs_strerror(errno));
        goto err_slot;
    }
    subtbl_fd = bpf_create_map_name(BPF_MAP_TYPE_HASH, subtbl_name,
                                    netdev_xdp_info->key_size,
                                    netdev_xdp_info->max_actions_len,
                                    netdev_xdp_info->max_entries, 0);
    if (subtbl_fd < 0) {
        err = errno;
        VLOG_ERR_RL(&rl, "map creation for subtbl failed: %s",
                    ovs_strerror(errno));
        goto err_slot;
    }

    tmp_values = xzalloc(netdev_xdp_info->key_size);
    memcpy(tmp_values, miniflow_get_values(minimatch.flow), key_size);
    if (bpf_map_update_elem(subtbl_fd, tmp_values, xdp_actions, 0)) {
        err = errno;
        VLOG_ERR_RL(&rl, "Cannot insert flow entry: %s", ovs_strerror(errno));
        free(tmp_values);
        goto err_close_slot;
    }
    free(tmp_values);

    if (bpf_map_update_elem(flow_table_fd, &free_slot, &subtbl_fd, 0)) {
        err = errno;
        VLOG_ERR_RL(&rl, "Failed to insert subtbl into flow_table: %s",
                    ovs_strerror(errno));
        goto err_close_slot;
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
err_close_slot:
    close(subtbl_fd);
err_slot:
    id_pool_free_id(netdev_xdp_info->free_slots, free_slot);

    goto err_entry;
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
    /* TODO: Implement this */
    return 0;
}

static int
netdev_xdp_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                    struct dpif_flow_stats *stats OVS_UNUSED)
{
    struct netdev_xdp_info *netdev_xdp_info;
    struct bpf_object *obj = get_xdp_object(netdev);
    size_t hash;
    struct ufid_to_xdp_data *data;
    int masks_fd, head_fd, flow_table_fd, subtbl_fd, head;
    struct xdp_subtable_mask_header *entry, *pentry;
    int err, cnt, idx, pidx;
    __u32 id;

    netdev_xdp_info = get_netdev_xdp_info(netdev);
    if (!netdev_xdp_info) {
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
    HMAP_FOR_EACH_WITH_HASH (data, ufid_node, hash, &ufid_to_xdp) {
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

    entry = xzalloc(netdev_xdp_info->subtable_mask_size);
    pentry = xzalloc(netdev_xdp_info->subtable_mask_size);

    /* Iterate subtable mask list implemented using array */
    idx = head;
    for (cnt = 0; cnt < netdev_xdp_info->max_subtables; cnt++) {
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

        memcpy(pentry, entry, netdev_xdp_info->subtable_mask_size);
        pidx = idx;
        idx = entry->next;
    }

    if (cnt == netdev_xdp_info->max_subtables) {
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

    if (entry->count == UINT16_MAX) {
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
    id_pool_free_id(netdev_xdp_info->free_slots, (uint32_t)idx);
out:
    free(data);
    free(pentry);
    free(entry);

    return err;
}

static int
netdev_xdp_init_flow_api(struct netdev *netdev)
{
    static struct ovsthread_once devmap_idx_once = OVSTHREAD_ONCE_INITIALIZER;
    struct bpf_object *obj;
    struct btf *btf;
    struct netdev_xdp_info *netdev_xdp_info;
    struct bpf_map *flow_table, *subtbl_template, *subtbl_masks;
    const struct bpf_map_def *flow_table_def, *subtbl_def, *subtbl_masks_def;
    odp_port_t port;
    size_t port_hash;
    int output_map_fd;
    int err, ifindex;
    uint32_t devmap_idx;

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

    netdev_xdp_info = find_netdev_xdp_info(port);
    if (netdev_xdp_info) {
        VLOG_ERR("xdp offload is already initialized for netdev %s",
                 netdev_get_name(netdev));
        return EEXIST;
    }

    if (ovsthread_once_start(&devmap_idx_once)) {
        devmap_idx_pool = id_pool_create(0, XDP_MAX_PORTS);
        ovsthread_once_done(&devmap_idx_once);
    }

    if (!id_pool_alloc_id(devmap_idx_pool, &devmap_idx)) {
        VLOG_ERR("Failed to get new devmap idx");
        return ENOSPC;
    }

    netdev_xdp_info = xzalloc(sizeof *netdev_xdp_info);
    netdev_xdp_info->devmap_idx = (int)devmap_idx;

    if (get_odp_port(netdev, &netdev_xdp_info->port) ||
        !netdev_xdp_info->port) {
        VLOG_ERR("Failed to get odp_port for %s", netdev_get_name(netdev));
        err = ENOENT;
        goto err;
    }

    obj = get_xdp_object(netdev);
    btf = bpf_object__btf(obj);
    if (!btf) {
        VLOG_ERR("BUG: BPF object for netdev \"%s\" does not contain BTF",
                 netdev_get_name(netdev));
        err = EINVAL;
        goto err;
    }

    err = probe_meta_info(netdev_xdp_info, btf);
    if (err) {
        VLOG_ERR("Failed to initialize xdp offload metadata for %s",
                 netdev_get_name(netdev));
        goto err;
    }

    flow_table = bpf_object__find_map_by_name(obj, "flow_table");
    if (!flow_table) {
        VLOG_ERR("BUG: BPF map \"flow_table\" not found");
        err = ENOENT;
        goto err;
    }
    flow_table_def = bpf_map__def(flow_table);
    if (flow_table_def->max_entries > XDP_MAX_SUBTABLES) {
        VLOG_ERR("flow_table max_entries must not be greater than %d",
                 XDP_MAX_SUBTABLES);
        goto err;
    }
    netdev_xdp_info->max_subtables = flow_table_def->max_entries;

    subtbl_template = bpf_object__find_map_by_name(obj, "subtbl_template");
    if (!subtbl_template) {
        VLOG_ERR("BUG: BPF map \"subtbl_template\" not found");
        err = ENOENT;
        goto err;
    }
    subtbl_def = bpf_map__def(subtbl_template);
    netdev_xdp_info->key_size = subtbl_def->key_size;
    netdev_xdp_info->max_actions_len = subtbl_def->value_size;
    netdev_xdp_info->max_entries = subtbl_def->max_entries;

    subtbl_masks = bpf_object__find_map_by_name(obj, "subtbl_masks");
    if (!subtbl_masks) {
        VLOG_ERR("BPF map \"subtbl_masks\" not found");
        err = ENOENT;
        goto err;
    }
    subtbl_masks_def = bpf_map__def(subtbl_masks);
    if (subtbl_masks_def->max_entries != netdev_xdp_info->max_subtables) {
        VLOG_ERR("\"subtbl_masks\" map has different max_entries from "
                 "\"flow_table\"");
        goto err;
    }
    netdev_xdp_info->subtable_mask_size = subtbl_masks_def->value_size;
    netdev_xdp_info->free_slots =
        id_pool_create(0, netdev_xdp_info->max_subtables);

    err = get_output_map_fd(obj, &output_map_fd);
    if (err) {
        goto err;
    }
    if (bpf_map_update_elem(output_map_fd, &devmap_idx, &ifindex, 0)) {
        err = errno;
        VLOG_ERR("Failed to insert idx %u if %s into output_map: %s",
                 devmap_idx, netdev_get_name(netdev), ovs_strerror(errno));
        goto err;
    }

    port_hash = hash_bytes(&port, sizeof port, 0);
    hmap_insert(&netdev_xdp_info_table, &netdev_xdp_info->port_node,
                port_hash);

    return 0;
err:
    free(netdev_xdp_info);
    id_pool_free_id(devmap_idx_pool, devmap_idx);
    return err;
}

static void
netdev_xdp_uninit_flow_api(struct netdev *netdev)
{
    struct bpf_object *obj;
    struct netdev_xdp_info *netdev_xdp_info;
    int output_map_fd, devmap_idx;

    netdev_xdp_info = get_netdev_xdp_info(netdev);
    if (!netdev_xdp_info) {
        VLOG_WARN("%s: netdev_xdp_info not found on uninitializing "
                  "xdp flow api",
                  netdev_get_name(netdev));
        return;
    }
    hmap_remove(&netdev_xdp_info_table, &netdev_xdp_info->port_node);

    devmap_idx = netdev_xdp_info->devmap_idx;
    obj = get_xdp_object(netdev);
    if (!get_output_map_fd(obj, &output_map_fd)) {
        bpf_map_delete_elem(output_map_fd, &devmap_idx);
    } else {
        VLOG_WARN("%s: Failed to get output_map fd on uninitializing xdp "
                  "flow api",
                  netdev_get_name(netdev));
    }

    id_pool_destroy(netdev_xdp_info->free_slots);
    free(netdev_xdp_info);
    id_pool_free_id(devmap_idx_pool, (uint32_t)devmap_idx);
}

const struct netdev_flow_api netdev_offload_xdp = {
    .type = "linux_xdp",
    .flow_put = netdev_xdp_flow_put,
    .flow_get = netdev_xdp_flow_get,
    .flow_del = netdev_xdp_flow_del,
    .init_flow_api = netdev_xdp_init_flow_api,
    .uninit_flow_api = netdev_xdp_uninit_flow_api,
};
