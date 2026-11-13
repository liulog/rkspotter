// SPDX-License-Identifier: GPL-2.0
/*
 * rkspotter - RISC-V/Linux 6.x port of the rootkit-spotter module.
 *
 * Upstream walked the module virtual-address window once from init_module()
 * and inspected every struct module it found there. This port keeps that
 * lookup: there is no copied module list and no extra reference on a target.
 * The walk is split across hardware IRQs because the IEE callback runs with
 * interrupts disabled and must not allocate or sleep. One completed pass of
 * the window is one upstream look_for_lkm().
 *
 * The x86 "mov %rax, %cr0" text signature has no RISC-V equivalent and is not
 * scanned. Process environments and /etc/ld.so.preload still need to sleep,
 * so those checks run once from insmod, which is where upstream ran them.
 */

#include <linux/align.h>
#include <linux/atomic.h>
#include <linux/bits.h>
#include <linux/fs.h>
#include <linux/iee_security.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/poison.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/unistd.h>

typedef struct module *(*module_address_fn_t)(unsigned long addr);
typedef unsigned long (*lookup_name_fn_t)(const char *name);

/* One IRQ advances this many pages. A full window walk is one scan_runs tick. */
#define RKSPOTTER_PAGES_PER_IRQ	8192
#define RKSPOTTER_REPORTS	24

static module_address_fn_t module_address_fn;
static void **syscall_table;
static unsigned long window_start;
static unsigned long window_end;

static atomic64_t scan_runs;
static atomic64_t suspect_modules;

static int rkspotter_counter_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%lld\n", atomic64_read(kp->arg));
}
static const struct kernel_param_ops counter_ops = { .get = rkspotter_counter_get };
module_param_cb(scan_runs, &counter_ops, &scan_runs, 0444);

enum {
	RK_LIST = BIT(0),
	RK_SYSFS = BIT(1),
	RK_ATTRS = BIT(2),
	RK_SIG = BIT(3),
};

struct rk_report {
	char name[MODULE_NAME_LEN];
	u8 reason;
};

struct rk_cpu_state {
	unsigned long cursor;
	struct module *last_mod;
	struct rk_report reports[RKSPOTTER_REPORTS];
	unsigned int count;
	bool overflow;
};

static struct rk_cpu_state cpu_state[NR_CPUS];

struct encoded_signature {
	const u8 *data;
	u8 len;
};

static const u8 signature_0[] = {
	0x8a, 0xd7, 0xc0, 0xd5, 0xd1, 0xcc, 0xc9, 0xc0, 0x8a, 0xd7, 0xc0, 0xd5, 0xd1, 0xcc, 0xc9, 0xc0,
};
static const u8 signature_1[] = { 0xee, 0xed, 0xea, 0xea, 0xee, 0xfa };
static const u8 signature_2[] = {
	0xcc, 0xd6, 0xfa, 0xd5, 0xd7, 0xca, 0xc6, 0xfa, 0xcc, 0xcb, 0xd3, 0xcc, 0xd6, 0xcc, 0xc7, 0xc9, 0xc0,
};
static const u8 signature_3[] = {
	0xf7, 0xea, 0xea, 0xf1, 0xee, 0xec, 0xf1, 0x85, 0xd6, 0xdc, 0xd6, 0xc6, 0xc4, 0xc9, 0xc9, 0xfa, 0xd1, 0xc4, 0xc7, 0xc9, 0xc0,
};
static const u8 signature_4[] = {
	0xf7, 0xea, 0xea, 0xf1, 0xee, 0xec, 0xf1, 0x85, 0xd6, 0xdc, 0xd6, 0xfa, 0xc6, 0xc4, 0xc9, 0xc9, 0xfa, 0xd1, 0xc4, 0xc7, 0xc9, 0xc0,
};
static const u8 signature_5[] = {
	0xd0, 0xcb, 0xfa, 0xcd, 0xcc, 0xcf, 0xc4, 0xc6, 0xce, 0xfa, 0xc0, 0xdd, 0xc0, 0xc6, 0xd3, 0xc0,
};
static const u8 signature_6[] = { 0xe2, 0xcc, 0xd3, 0xcc, 0xcb, 0xc2, 0x85, 0xd7, 0x95, 0x95, 0xd1 };
static const u8 signature_7[] = { 0xfe, 0x9a, 0xf8, 0x85, 0xf6, 0xe6, 0xf1, 0x9f };
static const u8 signature_8[] = {
	0xe0, 0xdd, 0xc4, 0xc8, 0xd5, 0xc9, 0xc0, 0x85, 0xf7, 0xca, 0xca, 0xd1, 0xce, 0xcc, 0xd1,
};
static const u8 signature_9[] = { 0xc2, 0xcc, 0xd3, 0xc0, 0xc8, 0xc0, 0xd7, 0xca, 0xca, 0xd1 };
static const u8 signature_10[] = {
	0x85, 0xc9, 0xcc, 0xc9, 0xdc, 0xca, 0xc3, 0xd1, 0xcd, 0xc0, 0xd3, 0xc4, 0xc9, 0xc9, 0xc0, 0xdc,
};
static const u8 signature_11[] = {
	0x85, 0xd0, 0x85, 0xd2, 0xc4, 0xcb, 0xd1, 0x85, 0xd1, 0xca, 0x85, 0xcd, 0xcc, 0xc1, 0xc0,
};
static const u8 signature_12[] = {
	0xc1, 0xcc, 0xc4, 0xc8, 0xca, 0xd7, 0xd5, 0xcd, 0xcc, 0xcb, 0xc0, 0xfa,
};
static const u8 signature_13[] = { 0xc8, 0x95, 0xcb, 0xc4, 0xc1 };
static const u8 signature_14[] = { 0xe9, 0xee, 0xe8, 0x85, 0xd7, 0xca, 0xca, 0xd1, 0xce, 0xcc, 0xd1 };
static const u8 signature_15[] = {
	0xfa, 0xc7, 0xc4, 0xc6, 0xce, 0xc1, 0xca, 0xca, 0xd7, 0xfa, 0xd0, 0xd6, 0xc0, 0xd7,
};
static const u8 signature_16[] = { 0x8a, 0xcd, 0xca, 0xc8, 0xc0, 0x8a, 0xcd, 0xc4, 0xdd, 0xca, 0xd7 };
static const u8 signature_17[] = {
	0x8a, 0xc0, 0xd1, 0xc6, 0x8a, 0xd6, 0xc0, 0xc6, 0xd7, 0xc0, 0xd1, 0xd6, 0xcd, 0xc4, 0xc1, 0xca, 0xd2,
};
static const u8 signature_18[] = {
	0xcd, 0xcc, 0xc1, 0xc0, 0x85, 0xd5, 0xcc, 0xc1, 0x85, 0xc6, 0xca, 0xc8, 0xc8, 0xc4, 0xcb, 0xc1,
};
static const u8 signature_19[] = {
	0xcd, 0xcc, 0xc1, 0xc0, 0x85, 0xc3, 0xcc, 0xc9, 0xc0, 0x85, 0xc6, 0xca, 0xc8, 0xc8, 0xc4, 0xcb, 0xc1,
};
static const u8 signature_20[] = {
	0xc4, 0xd6, 0xc8, 0xfa, 0xcd, 0xca, 0xca, 0xce, 0xfa, 0xd7, 0xc0, 0xc8, 0xca, 0xd3, 0xc0, 0xfa, 0xc4, 0xc9, 0xc9,
};
static const u8 signature_21[] = { 0xd7, 0x95, 0x95, 0xd1, 0xce, 0xcc, 0xd1 };
static const u8 signature_22[] = { 0xd7, 0x95, 0x95, 0xd1, 0xce, 0x94, 0xd1 };
static const u8 signature_23[] = { 0xc8, 0xca, 0xc1, 0xd0, 0xc9, 0xc0, 0xfa, 0xcd, 0xcc, 0xc1, 0xc0 };

static const struct encoded_signature suspicious_signatures[] = {
	{ signature_0, ARRAY_SIZE(signature_0) },
	{ signature_1, ARRAY_SIZE(signature_1) },
	{ signature_2, ARRAY_SIZE(signature_2) },
	{ signature_3, ARRAY_SIZE(signature_3) },
	{ signature_4, ARRAY_SIZE(signature_4) },
	{ signature_5, ARRAY_SIZE(signature_5) },
	{ signature_6, ARRAY_SIZE(signature_6) },
	{ signature_7, ARRAY_SIZE(signature_7) },
	{ signature_8, ARRAY_SIZE(signature_8) },
	{ signature_9, ARRAY_SIZE(signature_9) },
	{ signature_10, ARRAY_SIZE(signature_10) },
	{ signature_11, ARRAY_SIZE(signature_11) },
	{ signature_12, ARRAY_SIZE(signature_12) },
	{ signature_13, ARRAY_SIZE(signature_13) },
	{ signature_14, ARRAY_SIZE(signature_14) },
	{ signature_15, ARRAY_SIZE(signature_15) },
	{ signature_16, ARRAY_SIZE(signature_16) },
	{ signature_17, ARRAY_SIZE(signature_17) },
	{ signature_18, ARRAY_SIZE(signature_18) },
	{ signature_19, ARRAY_SIZE(signature_19) },
	{ signature_20, ARRAY_SIZE(signature_20) },
	{ signature_21, ARRAY_SIZE(signature_21) },
	{ signature_22, ARRAY_SIZE(signature_22) },
	{ signature_23, ARRAY_SIZE(signature_23) },
};

struct watched_syscall {
	int nr;
	const char *name;
	bool hit;
};

static struct watched_syscall watched_syscalls[] = {
	{ __NR_openat, "sys_openat", false },
	{ __NR_getdents64, "sys_getdents64", false },
	{ __NR_readlinkat, "sys_readlinkat", false },
};

static unsigned long rkspotter_symbol(const char *name)
{
	struct kprobe probe = { .symbol_name = name };
	unsigned long address = 0;

	if (register_kprobe(&probe))
		return 0;
	address = (unsigned long)probe.addr;
	unregister_kprobe(&probe);
	return address;
}

static bool notrace rkspotter_signatures(const u8 *data, unsigned int length)
{
	unsigned int i, j, k;

	for (i = 0; i < ARRAY_SIZE(suspicious_signatures); i++) {
		const struct encoded_signature *sig = &suspicious_signatures[i];

		if (length < sig->len)
			continue;
		for (j = 0; j <= length - sig->len; j++) {
			for (k = 0; k < sig->len; k++)
				if (READ_ONCE(data[j + k]) != (sig->data[k] ^ 0xa5))
					break;
			if (k == sig->len)
				return true;
		}
	}
	return false;
}

static void notrace rkspotter_remember(struct rk_cpu_state *st, const char *name, u8 reason)
{
	unsigned int i;

	for (i = 0; i < st->count; i++) {
		if (!strcmp(st->reports[i].name, name)) {
			st->reports[i].reason |= reason;
			return;
		}
	}
	if (st->count >= ARRAY_SIZE(st->reports)) {
		st->overflow = true;
		return;
	}
	strscpy(st->reports[st->count].name, name, MODULE_NAME_LEN);
	st->reports[st->count].reason = reason;
	st->count++;
}

/* Read the live struct module. Do not retain it after this call returns. */
static void notrace rkspotter_inspect(struct rk_cpu_state *st, struct module *mod)
{
	unsigned long next = (unsigned long)READ_ONCE(mod->list.next);
	unsigned long prev = (unsigned long)READ_ONCE(mod->list.prev);
	u8 reason = 0;
	int type;

	if (next == (unsigned long)LIST_POISON1 ||
	    prev == (unsigned long)LIST_POISON2 || next == prev)
		reason |= RK_LIST;
	if (!mod->mkobj.kobj.state_in_sysfs)
		reason |= RK_SYSFS;
#ifdef CONFIG_KALLSYMS
	/*
	 * Upstream also treats notes_attrs == NULL as suspect. A module with
	 * no SHT_NOTE section never allocates that pointer, so only a cleared
	 * section-attribute pointer is treated as tampering here.
	 */
	if (!mod->sect_attrs)
		reason |= RK_ATTRS;
#endif
	if (mod != THIS_MODULE) {
		for (type = MOD_DATA; type <= MOD_RO_AFTER_INIT; type++) {
			const struct module_memory *mem = &mod->mem[type];

			if (!mem->size)
				continue;
			if (rkspotter_signatures(mem->base, mem->size))
				reason |= RK_SIG;
		}
	}
	if (!reason)
		return;
	atomic64_inc(&suspect_modules);
	rkspotter_remember(st, mod->name, reason);
}

static unsigned long notrace rkspotter_skip(struct module *mod, unsigned long addr)
{
	unsigned long next = addr + PAGE_SIZE;
	int type;

	for (type = 0; type < MOD_MEM_NUM_TYPES; type++) {
		unsigned long base = (unsigned long)mod->mem[type].base;
		unsigned long size = mod->mem[type].size;
		unsigned long end;

		if (!base || !size)
			continue;
		end = base + size;
		if (addr >= base && addr < end && end > next)
			next = end;
	}
	return next;
}

static void notrace rkspotter_syscalls(void)
{
	unsigned int i;

	if (!syscall_table)
		return;
	for (i = 0; i < ARRAY_SIZE(watched_syscalls); i++) {
		unsigned long entry;
		int nr = watched_syscalls[i].nr;

		if (nr < 0 || nr >= __NR_syscalls)
			continue;
		entry = (unsigned long)READ_ONCE(syscall_table[nr]);
		if (entry >= window_start && entry < window_end)
			WRITE_ONCE(watched_syscalls[i].hit, true);
	}
}

static void notrace rkspotter_scan(struct rk_cpu_state *st)
{
	unsigned long slice, addr;

	if (st->cursor < window_start || st->cursor >= window_end) {
		st->cursor = window_start;
		st->last_mod = NULL;
	}
	slice = st->cursor + ((unsigned long)RKSPOTTER_PAGES_PER_IRQ << PAGE_SHIFT);
	if (slice < st->cursor || slice > window_end)
		slice = window_end;

	addr = st->cursor;
	while (addr < slice) {
		struct module *mod = module_address_fn(addr);
		unsigned long next;

		if (!mod) {
			st->last_mod = NULL;
			addr += PAGE_SIZE;
			continue;
		}
		if (mod != st->last_mod) {
			st->last_mod = mod;
			rkspotter_inspect(st, mod);
		}
		next = rkspotter_skip(mod, addr);
		if (next <= addr)
			next = addr + PAGE_SIZE;
		if (next > slice || next < addr)
			next = slice;
		addr = next;
	}
	st->cursor = slice;
	if (st->cursor >= window_end) {
		rkspotter_syscalls();
		st->cursor = window_start;
		st->last_mod = NULL;
		atomic64_inc(&scan_runs);
	}
}

static void notrace rkspotter_interrupt(void)
{
	unsigned int cpu = smp_processor_id();

	if (cpu >= ARRAY_SIZE(cpu_state) || !module_address_fn)
		return;
	rkspotter_scan(&cpu_state[cpu]);
}

static const struct iee_security_ops rkspotter_ops = {
	.interrupt = rkspotter_interrupt,
};

static bool rkspotter_preload_file(void)
{
	struct path path;
	bool found = false;

	if (kern_path("/etc/ld.so.preload", 0, &path))
		return false;
	if (d_is_reg(path.dentry) && i_size_read(d_inode(path.dentry)) > 0)
		found = true;
	path_put(&path);
	return found;
}

/* Upstream look_for_userspace(): sleep and allocation stay in process context. */
static void rkspotter_userspace(void)
{
	char *needle = "LD_PRELOAD";
	int nr;

	for (nr = 2; nr < PID_MAX_DEFAULT; nr++) {
		struct task_struct *task;
		struct mm_struct *mm;
		unsigned long start, end, size;
		char comm[TASK_COMM_LEN];
		void *buf;

		rcu_read_lock();
		task = pid_task(find_vpid(nr), PIDTYPE_PID);
		if (task)
			get_task_struct(task);
		rcu_read_unlock();
		if (!task)
			continue;

		get_task_comm(comm, task);
		mm = get_task_mm(task);
		if (!mm)
			goto put_task;
		start = mm->env_start;
		end = mm->env_end;
		mmput(mm);
		if (end <= start)
			goto put_task;
		size = end - start;
		if (size <= 16 || size > SZ_1M)
			goto put_task;
		buf = kvmalloc(size, GFP_KERNEL);
		if (!buf)
			goto put_task;
		if (access_process_vm(task, start, buf, (int)size, FOLL_FORCE) > 0 &&
		    strnstr(buf, needle, size))
			pr_info("rkspotter: process %d (%s) has LD_PRELOAD environment var\n",
				nr, comm);
		kvfree(buf);
put_task:
		put_task_struct(task);
		cond_resched();
	}

	if (rkspotter_preload_file())
		pr_info("rkspotter: found /etc/ld.so.preload exists and is not empty\n");
}

static void rkspotter_print_reason(const struct rk_report *report)
{
	pr_warn("rkspotter: suspicious module %s%s%s%s%s\n",
		report->name,
		report->reason & RK_LIST ? " list" : "",
		report->reason & RK_SYSFS ? " sysfs" : "",
		report->reason & RK_ATTRS ? " attrs" : "",
		report->reason & RK_SIG ? " signature" : "");
}

static int __init rkspotter_init(void)
{
	lookup_name_fn_t lookup;
	int ret;

	module_address_fn = (module_address_fn_t)rkspotter_symbol("__module_address");
	if (!module_address_fn)
		return -ENOENT;

	lookup = (lookup_name_fn_t)rkspotter_symbol("kallsyms_lookup_name");
	if (lookup)
		syscall_table = (void **)lookup("sys_call_table");

	window_start = ALIGN_DOWN((unsigned long)THIS_MODULE->mem[MOD_TEXT].base, SZ_2G);
	window_end = window_start + SZ_2G;

	rkspotter_userspace();

	ret = iee_security_register(&rkspotter_ops);
	if (ret)
		return ret;

	pr_info("rkspotter: module window [%lx, %lx), %u pages per interrupt\n",
		window_start, window_end, RKSPOTTER_PAGES_PER_IRQ);
	if (!syscall_table)
		pr_info("rkspotter: sys_call_table not found, syscall checks disabled\n");
	return 0;
}

static bool rkspotter_already_printed(unsigned int cpu, unsigned int index)
{
	unsigned int earlier, i;
	const char *name = cpu_state[cpu].reports[index].name;

	for (earlier = 0; earlier < cpu; earlier++) {
		for (i = 0; i < cpu_state[earlier].count; i++)
			if (!strcmp(cpu_state[earlier].reports[i].name, name))
				return true;
	}
	for (i = 0; i < index; i++)
		if (!strcmp(cpu_state[cpu].reports[i].name, name))
			return true;
	return false;
}

static void __exit rkspotter_exit(void)
{
	unsigned int cpu, i;
	bool overflow = false;

	iee_security_unregister(&rkspotter_ops);

	for (cpu = 0; cpu < ARRAY_SIZE(cpu_state); cpu++) {
		overflow |= cpu_state[cpu].overflow;
		for (i = 0; i < cpu_state[cpu].count; i++) {
			if (rkspotter_already_printed(cpu, i))
				continue;
			rkspotter_print_reason(&cpu_state[cpu].reports[i]);
		}
	}
	if (overflow)
		pr_warn("rkspotter: suspect table overflowed\n");
	for (i = 0; i < ARRAY_SIZE(watched_syscalls); i++)
		if (READ_ONCE(watched_syscalls[i].hit))
			pr_warn("rkspotter: syscall table %s entry points to a module\n",
				watched_syscalls[i].name);
	pr_info("rkspotter: unloaded, scans=%lld suspects=%lld\n",
		atomic64_read(&scan_runs),
		atomic64_read(&suspect_modules));
}

module_init(rkspotter_init);
module_exit(rkspotter_exit);

MODULE_AUTHOR("linuxthor; RISC-V IEE port");
MODULE_DESCRIPTION("IEE module-window rootkit detector");
MODULE_LICENSE("GPL");
