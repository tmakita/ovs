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

#ifndef BPF_MINIFLOW_H
#define BPF_MINIFLOW_H 1

#include "flow.h"

/* FIXME: copied from lib/util.h */
/* FIXME: need to be 32-bit compatible */
/* unsigned int count_1bits(uint64_t x):
 *
 * Returns the number of 1-bits in 'x', between 0 and 64 inclusive. */
static inline unsigned int
bpf_count_1bits(uint64_t x)
{
    /* This portable implementation is the fastest one we know of for 64
     * bits, and about 3x faster than GCC 4.7 __builtin_popcountll(). */
    const uint64_t h55 = UINT64_C(0x5555555555555555);
    const uint64_t h33 = UINT64_C(0x3333333333333333);
    const uint64_t h0F = UINT64_C(0x0F0F0F0F0F0F0F0F);
    const uint64_t h01 = UINT64_C(0x0101010101010101);
    x -= (x >> 1) & h55;               /* Count of each 2 bits in-place. */
    x = (x & h33) + ((x >> 2) & h33);  /* Count of each 4 bits in-place. */
    x = (x + (x >> 4)) & h0F;          /* Count of each 8 bits in-place. */
    return (x * h01) >> 56;            /* Sum of all bytes. */
}

struct bpf_mf_ctx {
    struct flowmap map;
    uint64_t *data;
};

static inline void
miniflow_set_maps(struct bpf_mf_ctx *ctx, size_t ofs, size_t n_words)
{
    flowmap_set(&ctx->map, ofs, n_words);
}

static inline void
miniflow_set_map(struct bpf_mf_ctx *ctx, size_t ofs)
{
    flowmap_set(&ctx->map, ofs, 1);
}

static inline void
miniflow_push_uint8_(struct bpf_mf_ctx *ctx, size_t ofs, uint8_t value)
{
    size_t ofs8 = ofs % 8;

    if (ofs8 == 0) {
        miniflow_set_map(ctx, ofs / 8);
    }
    *((uint8_t *)ctx->data + ofs8) = value;
    if (ofs8 == 7) {
        ctx->data++;
    }
}

static inline void
miniflow_push_uint16_(struct bpf_mf_ctx *ctx, size_t ofs, uint16_t value)
{
    size_t ofs8 = ofs % 8;

    if (ofs8 == 0) {
        miniflow_set_map(ctx, ofs / 8);
        *(uint16_t *)ctx->data = value;
    } else if (ofs8 == 2) {
        *((uint16_t *)ctx->data + 1) = value;
    } else if (ofs8 == 4) {
        *((uint16_t *)ctx->data + 2) = value;
    } else if (ofs8 == 6) {
        *((uint16_t *)ctx->data + 3) = value;
        ctx->data++;
    }
}

static inline void
miniflow_push_uint32_(struct bpf_mf_ctx *ctx, size_t ofs, uint32_t value)
{
    size_t ofs8 = ofs % 8;

    if (ofs8 == 0) {
        miniflow_set_map(ctx, ofs / 8);
        *(uint32_t *)ctx->data = value;
    } else if (ofs8 == 4) {
        *((uint32_t *)ctx->data + 1) = value;
        ctx->data++;
    }
}

static inline void
ether_addr_copy(struct eth_addr *dst, const struct eth_addr *src)
{
    ovs_be16 *a = dst->be16;
    const ovs_be16 *b = src->be16;

    a[0] = b[0];
    a[1] = b[1];
    a[2] = b[2];
}

/* 'valuep' is 16-aligned */
/* data must start 64-aligned and must be followed by other data or padding */
static inline void
miniflow_push_macs_(struct bpf_mf_ctx *ctx, size_t ofs,
                    const struct eth_addr *valuep)
{
    miniflow_set_maps(ctx, ofs / 8, 2);
    ether_addr_copy((struct eth_addr *)ctx->data, valuep);
    ether_addr_copy((struct eth_addr *)ctx->data + 1, valuep + 1);
    ctx->data++; /* First word only. */
}

/* data must start 64-aligned and must be followed by other data */
static inline void
miniflow_pad_from_64_(struct bpf_mf_ctx *ctx, size_t ofs)
{
    size_t ofs8 = ofs % 8;
    size_t ofs4 = ofs % 4;
    size_t ofs2 = ofs % 2;
    void *cdata = ctx->data;

    miniflow_set_map(ctx, ofs / 8);

    if (ofs8 >= 4) {
        *(uint32_t *)cdata = 0;
        cdata += 4;
    }
    if (ofs4 >= 2) {
        *(uint16_t *)cdata = 0;
        cdata += 2;
    }
    if (ofs2 == 1) {
        *(uint8_t *)cdata = 0;
    }
}

static inline void
miniflow_pad_to_64_(struct bpf_mf_ctx *ctx, size_t ofs)
{
    size_t ofs8 = ofs % 8;
    size_t ofs4 = ofs % 4;
    size_t ofs2 = ofs % 2;
    void *cdata = ctx->data;

    cdata += ofs8;
    if (ofs2 == 1) {
        *(uint8_t *)cdata = 0;
        cdata++;
    }
    if (ofs4 <= 2) {
        *(uint16_t *)cdata = 0;
        cdata += 2;
    }
    if (ofs8 <= 4) {
        *(uint32_t *)cdata = 0;
    }
    ctx->data++;
}

#define miniflow_push_uint8(CTX, FIELD, VALUE)                       \
    miniflow_push_uint8_(CTX, offsetof(struct flow, FIELD), VALUE)

#define miniflow_push_be16_(CTX, OFS, VALUE)                         \
    miniflow_push_uint16_(CTX, OFS, (OVS_FORCE uint16_t)VALUE)

#define miniflow_push_be16(CTX, FIELD, VALUE)                        \
    miniflow_push_be16_(CTX, offsetof(struct flow, FIELD), VALUE)    \

#define miniflow_push_be32_(CTX, OFS, VALUE)                         \
    miniflow_push_uint32_(CTX, OFS, (OVS_FORCE uint32_t)VALUE)

#define miniflow_push_be32(CTX, FIELD, VALUE)                        \
    miniflow_push_be32_(CTX, offsetof(struct flow, FIELD), VALUE)    \

#define miniflow_push_macs(CTX, FIELD, VALUEP)                       \
    miniflow_push_macs_(CTX, offsetof(struct flow, FIELD), VALUEP)

#define miniflow_pad_from_64(CTX, FIELD)                             \
    miniflow_pad_from_64_(CTX, offsetof(struct flow, FIELD))

#define miniflow_pad_to_64(CTX, FIELD)                               \
    miniflow_pad_to_64_(CTX, OFFSETOFEND(struct flow, FIELD))

#endif /* bpf_miniflow.h */
