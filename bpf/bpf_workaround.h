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

#ifndef BPF_WORKAROUND_H
#define BPF_WORKAROUND_H

/* On Linux x86/x64 systems bits/wordsize.h included from stdint.h cannot
 * correctly determine __WORDSIZE for bpf, which causes incorrect UINTPTR_MAX
 */
#if __UINTPTR_MAX__ == __UINT64_MAX__ && defined(UINTPTR_MAX)
#undef UINTPTR_MAX
#define UINTPTR_MAX UINT64_MAX
#endif

#endif /* bpf_workaround.h */
