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

#include "bpf-util.h"

#include <bpf/libbpf.h>

#include "ovs-thread.h"

DEFINE_STATIC_PER_THREAD_DATA(struct { char s[128]; },
                              libbpf_strerror_buffer,
                              { "" });

const char *
ovs_libbpf_strerror(int err)
{
    enum { BUFSIZE = sizeof libbpf_strerror_buffer_get()->s };
    char *buf = libbpf_strerror_buffer_get()->s;

    libbpf_strerror(err, buf, BUFSIZE);

    return buf;
}
