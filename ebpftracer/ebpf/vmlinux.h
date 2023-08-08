#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			__u64 regs[31];
			__u64 sp;
			__u64 pc;
			__u64 pstate;
		};
	};
	__u64 orig_x0;
	__s32 syscallno;
	__u32 unused2;
	__u64 orig_addr_limit;
	__u64 pmr_save;
	__u64 stackframe[2];
	__u64 lockdep_hardirqs;
	__u64 exit_rcu;
};
#endif

#endif /* __VMLINUX_H__ */