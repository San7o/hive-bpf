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
    long unsigned int *valp;
    long unsigned int ino = BPF_CORE_READ(inode, i_ino);
    valp = bpf_map_lookup_elem(&traced_inodes, &key);
		
		// https://www.sabi.co.uk/blog/21-two.html?210804#210804
    if (valp && *valp == ino)
    {
      __u64 pid_tgid = bpf_get_current_pid_tgid();
			__u64 uid_gid = bpf_get_current_uid_gid();
			
			pid_t pid = pid_tgid >> 32;
			gid_t tgid = (gid_t) pid_tgid;
			uid_t uid = uid_gid >> 32;
			gid_t gid = (gid_t) uid_gid;
			
      bpf_printk("{pid:%d,tgid:%d,uid:%d,gid:%d,ino:%ld,mask:%d}",
								 pid, tgid, uid, gid, ino, mask);
    }
    return 0;
}
