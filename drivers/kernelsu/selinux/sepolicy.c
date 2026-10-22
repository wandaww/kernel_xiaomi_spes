// SPDX-License-Identifier: GPL-2.0
/*
 * Kernels < 5.10 keep the SELinux policy in selinux_state.ss (flex_array tables, filename_trans
 * without key params, ...), which the code written for >= 5.10 cannot handle. The legacy
 * implementation comes from KernelSU-Next. Both are pulled in here so the Kbuild object list
 * stays unchanged.
 */
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include "sepolicy_modern.inc"
#else
#include "sepolicy_legacy.inc"
#endif
