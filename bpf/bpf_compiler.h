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

#ifndef BPF_COMPILER_H
#define BPF_COMPILER_H

/* Hint for compiler: make register value unknown to compiler and prevent
 * following code, e.g. bound check, from being omitted */
#define bpf_compiler_reg_barrier(val) __asm__ __volatile__("":"+r"(val));

#endif /* bpf_compiler.h */

