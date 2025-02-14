// SPDX-License-Identifier: GPL-2.0-only OR MIT
//go:build ignore

#include "vmlinux.h"
#include "maps.h"
#include "license.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("kprobe/inode_permission")
int kprobe_inode_permission(struct pt_regs *ctx)
// Probed function:
// int inode_permission(struct mnt_idmap *idmap,
//		     struct inode *inode, int mask)
// Description: Check if accessing an inode is allowed
{
    struct mnt_idmap *idmap = (struct mnt_idmap*) BPF_CORE_READ(ctx, di);
    struct inode *inode = (struct inode*) BPF_CORE_READ(ctx, si);
    int mask = (int) BPF_CORE_READ(ctx, dx);

    __u32 key = 0;
    __u64 initval = 1, *valp;
    long unsigned int ino = BPF_CORE_READ(inode, i_ino);
    valp = bpf_map_lookup_elem(&traced_inodes, &key);
    if (valp && *valp == ino)
    {
      int pid = bpf_get_current_pid_tgid() >> 32;
      bpf_printk("{pid = %d, inode = %ld\n}", pid, ino);
    }
    return 0;
}
