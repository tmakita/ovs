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

#include "openvswitch/compiler.h"

SEC("xdp") int
noop(struct xdp_md *ctx OVS_UNUSED)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "Apache-2.0";
