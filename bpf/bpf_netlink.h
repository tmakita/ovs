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

#ifndef BPF_NETLINK_H
#define BPF_NETLINK_H 1

#include "bpf_compiler.h"
#include "netlink.h"

static inline int
bpf_nl_attr_type(const struct nlattr *nla)
{
    return nla->nla_type & NLA_TYPE_MASK;
}

static inline const void *
bpf_nl_attr_get(const struct nlattr *nla)
{
    return nla + 1;
}

static inline size_t
bpf_map_nl_attr_next_offset(void *start, size_t offset, size_t max_len)
{
    const struct nlattr *nla;

    /* Use offset (scalar) to cap the bounds of nla pointer address (map_value)
     * because map_value's min/max cannot be set by cond jmp ops in verifier */
    bpf_compiler_reg_barrier(offset);
    if (offset > max_len - sizeof *nla) {
        return max_len;
    }

    nla = (const struct nlattr *)(start + offset);
    offset += NLA_ALIGN(nla->nla_len);
    if (offset >= max_len) {
        return max_len;
    }

    return offset;
}

/* NOTE: (IDX) < (MAX_ATTRS) is mandatory for verifier */
#define BPF_MAP_NL_ATTR_FOR_EACH(OFF, ATTRS, START, END, IDX, MAX_ATTRS, \
                                 MAX_LEN) \
    for ((IDX) = 0, (OFF) = (void *)(ATTRS) - (START); \
         (IDX) < (MAX_ATTRS) && (OFF) < (END) - (START); \
         (IDX)++, (OFF) = bpf_map_nl_attr_next_offset(START, OFF, MAX_LEN))

#endif /* bpf_netlink.h */
