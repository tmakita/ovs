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

#ifndef NETDEV_OFFLOAD_XDP_H
#define NETDEV_OFFLOAD_XDP_H 1

#include "flow.h"

#define XDP_MAX_PORTS 65536
/* XDP_MAX_SUBTABLES must be <= 255 to fit in 1 byte with 1 value reserved
 * for TAIL */
#define XDP_MAX_SUBTABLES 128
#define XDP_SUBTABLES_TAIL XDP_MAX_SUBTABLES

struct xdp_subtable_mask_header {
    uint16_t count;
    uint8_t mf_bits_u0;
    uint8_t mf_bits_u1;
    int next;
    struct minimask mask;
};

struct xdp_flow_actions_header {
    size_t actions_len;
    /* Followed by netlink attributes (actions) */
};

struct nlattr;

static inline struct nlattr *
xdp_flow_actions(struct xdp_flow_actions_header *header)
{
    return (struct nlattr *)(header + 1);
}

#endif /* netdev-offload-xdp.h */
