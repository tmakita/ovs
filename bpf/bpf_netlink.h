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

#endif /* bpf_netlink.h */
