// SPDX-License-Identifier: GPL-2.0
/* RISC-V IEE port: query module_memory's address tree; never probe holes. */
#ifdef CONFIG_IEE_RKSPOTTER

#include <linux/align.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/iee_security.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/poison.h>

#include <asm/haoc/iee-def.h>
#include <asm/page.h>
#include <asm/unistd.h>

#define RKSPOTTER_MAX_PAGES_PER_IRQ 64U
#define RKSPOTTER_SIG_MAX 32U

static unsigned int pages_per_irq = 64;
module_param(pages_per_irq, uint, 0444);
MODULE_PARM_DESC(pages_per_irq, "Page work budget per successful IRQ (1..64)");

static unsigned long cursor;
static unsigned long findings;
static unsigned long scan_runs;

static int scan_runs_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%lu\n",
			 READ_ONCE(*(unsigned long *)kp->arg));
}

static int findings_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "0x%lx\n",
			 READ_ONCE(*(unsigned long *)kp->arg));
}

static const struct kernel_param_ops scan_runs_ops = { .get = scan_runs_get };
static const struct kernel_param_ops findings_ops = { .get = findings_get };
module_param_cb(scan_runs, &scan_runs_ops, &scan_runs, 0444);
module_param_cb(findings, &findings_ops, &findings, 0444);

enum {
	RK_LIST = BIT(0),
	RK_SYSFS = BIT(1),
	RK_ATTRS = BIT(2),
	RK_SIG = BIT(3),
	RK_SYSCALL = BIT(4),
	RK_INCOMPLETE = BIT(5),
};

struct encoded_signature {
	const u8 *data;
	u8 len;
};

static const u8 signature_0[] = {
	0x8a, 0xd7, 0xc0, 0xd5, 0xd1, 0xcc, 0xc9, 0xc0, 0x8a, 0xd7, 0xc0, 0xd5,
	0xd1, 0xcc, 0xc9, 0xc0,
};

static const u8 signature_1[] = {
	0xee, 0xed, 0xea, 0xea, 0xee, 0xfa,
};

static const u8 signature_2[] = {
	0xcc, 0xd6, 0xfa, 0xd5, 0xd7, 0xca, 0xc6, 0xfa, 0xcc, 0xcb, 0xd3, 0xcc,
	0xd6, 0xcc, 0xc7, 0xc9, 0xc0,
};

static const u8 signature_3[] = {
	0xf7, 0xea, 0xea, 0xf1, 0xee, 0xec, 0xf1, 0x85, 0xd6, 0xdc, 0xd6, 0xc6,
	0xc4, 0xc9, 0xc9, 0xfa, 0xd1, 0xc4, 0xc7, 0xc9, 0xc0,
};

static const u8 signature_4[] = {
	0xf7, 0xea, 0xea, 0xf1, 0xee, 0xec, 0xf1, 0x85, 0xd6, 0xdc, 0xd6, 0xfa,
	0xc6, 0xc4, 0xc9, 0xc9, 0xfa, 0xd1, 0xc4, 0xc7, 0xc9, 0xc0,
};

static const u8 signature_5[] = {
	0xd0, 0xcb, 0xfa, 0xcd, 0xcc, 0xcf, 0xc4, 0xc6, 0xce, 0xfa, 0xc0, 0xdd,
	0xc0, 0xc6, 0xd3, 0xc0,
};

static const u8 signature_6[] = {
	0xe2, 0xcc, 0xd3, 0xcc, 0xcb, 0xc2, 0x85, 0xd7, 0x95, 0x95, 0xd1,
};

static const u8 signature_7[] = {
	0xfe, 0x9a, 0xf8, 0x85, 0xf6, 0xe6, 0xf1, 0x9f,
};

static const u8 signature_8[] = {
	0xe0, 0xdd, 0xc4, 0xc8, 0xd5, 0xc9, 0xc0, 0x85, 0xf7, 0xca, 0xca, 0xd1,
	0xce, 0xcc, 0xd1,
};

static const u8 signature_9[] = {
	0xc2, 0xcc, 0xd3, 0xc0, 0xc8, 0xc0, 0xd7, 0xca, 0xca, 0xd1,
};

static const u8 signature_10[] = {
	0x85, 0xc9, 0xcc, 0xc9, 0xdc, 0xca, 0xc3, 0xd1, 0xcd, 0xc0, 0xd3, 0xc4,
	0xc9, 0xc9, 0xc0, 0xdc,
};

static const u8 signature_11[] = {
	0x85, 0xd0, 0x85, 0xd2, 0xc4, 0xcb, 0xd1, 0x85, 0xd1, 0xca, 0x85, 0xcd,
	0xcc, 0xc1, 0xc0,
};

static const u8 signature_12[] = {
	0xc1, 0xcc, 0xc4, 0xc8, 0xca, 0xd7, 0xd5, 0xcd, 0xcc, 0xcb, 0xc0, 0xfa,
};

static const u8 signature_13[] = {
	0xc8, 0x95, 0xcb, 0xc4, 0xc1,
};

static const u8 signature_14[] = {
	0xe9, 0xee, 0xe8, 0x85, 0xd7, 0xca, 0xca, 0xd1, 0xce, 0xcc, 0xd1,
};

static const u8 signature_15[] = {
	0xfa, 0xc7, 0xc4, 0xc6, 0xce, 0xc1, 0xca, 0xca, 0xd7, 0xfa, 0xd0, 0xd6,
	0xc0, 0xd7,
};

static const u8 signature_16[] = {
	0x8a, 0xcd, 0xca, 0xc8, 0xc0, 0x8a, 0xcd, 0xc4, 0xdd, 0xca, 0xd7,
};

static const u8 signature_17[] = {
	0x8a, 0xc0, 0xd1, 0xc6, 0x8a, 0xd6, 0xc0, 0xc6, 0xd7, 0xc0, 0xd1, 0xd6,
	0xcd, 0xc4, 0xc1, 0xca, 0xd2,
};

static const u8 signature_18[] = {
	0xcd, 0xcc, 0xc1, 0xc0, 0x85, 0xd5, 0xcc, 0xc1, 0x85, 0xc6, 0xca, 0xc8,
	0xc8, 0xc4, 0xcb, 0xc1,
};

static const u8 signature_19[] = {
	0xcd, 0xcc, 0xc1, 0xc0, 0x85, 0xc3, 0xcc, 0xc9, 0xc0, 0x85, 0xc6, 0xca,
	0xc8, 0xc8, 0xc4, 0xcb, 0xc1,
};

static const u8 signature_20[] = {
	0xc4, 0xd6, 0xc8, 0xfa, 0xcd, 0xca, 0xca, 0xce, 0xfa, 0xd7, 0xc0, 0xc8,
	0xca, 0xd3, 0xc0, 0xfa, 0xc4, 0xc9, 0xc9,
};

static const u8 signature_21[] = {
	0xd7, 0x95, 0x95, 0xd1, 0xce, 0xcc, 0xd1,
};

static const u8 signature_22[] = {
	0xd7, 0x95, 0x95, 0xd1, 0xce, 0x94, 0xd1,
};

static const u8 signature_23[] = {
	0xc8, 0xca, 0xc1, 0xd0, 0xc9, 0xc0, 0xfa, 0xcd, 0xcc, 0xc1, 0xc0,
};

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

static __always_inline bool
rkspotter_signatures(const u8 *data, unsigned int length)
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

/* Called only for a live core module found in mod_tree, under RCU + kset lock. */
static __always_inline int
rkspotter_inspect_region(const struct iee_security_context *ctx,
			 struct module *mod, unsigned long addr,
			 unsigned int budget, unsigned int *used,
			 unsigned long *next_addr)
{
	unsigned long next = (unsigned long)READ_ONCE(mod->list.next);
	unsigned long prev = (unsigned long)READ_ONCE(mod->list.prev);
	int reason = 0;
	int type;

	if (next == (unsigned long)LIST_POISON1 ||
	    prev == (unsigned long)LIST_POISON2 ||
	    (next == prev && next != (unsigned long)ctx->modules))
		reason |= RK_LIST;
	if (!mod->mkobj.kobj.state_in_sysfs)
		reason |= RK_SYSFS;
#ifdef CONFIG_KALLSYMS
	/* Missing notes_attrs alone is normal for modules without ELF notes. */
	if (!READ_ONCE(mod->sect_attrs))
		reason |= RK_ATTRS;
#endif
	for (type = MOD_TEXT; type <= MOD_RO_AFTER_INIT; type++) {
		const struct module_memory *mem = &mod->mem[type];
		unsigned long base = (unsigned long)READ_ONCE(mem->base);
		unsigned long size = READ_ONCE(mem->size);
		unsigned long end;
		unsigned int pages = 0;

		if (!size || addr < base || addr - base >= size)
			continue;
		if (base < ctx->modules_start || base >= ctx->modules_end ||
		    size > ctx->modules_end - base)
			return reason | RK_INCOMPLETE;
		end = base + size;
		/* No payload reads for text or the checker's own data. */
		if (type == MOD_TEXT || mod == THIS_MODULE) {
			*next_addr = ALIGN(end, PAGE_SIZE);
			return reason;
		}
		/* Inspect this region once, stopping at the IRQ's remaining budget. */
		while (pages < budget && addr < end) {
			unsigned int length;

			/* Keep cross-page signatures within the same live region. */
			length = min_t(unsigned long, PAGE_SIZE + RKSPOTTER_SIG_MAX - 1,
				       end - addr);
			if (rkspotter_signatures((const u8 *)addr, length))
				reason |= RK_SIG;
			pages++;
			addr += PAGE_SIZE;
		}
		*used = pages;
		*next_addr = addr;
		return reason;
	}
	return reason | RK_INCOMPLETE;
}

static const unsigned int watched_syscalls[] = {
	__NR_openat, __NR_getdents64, __NR_readlinkat,
};

static __always_inline int
rkspotter_syscalls(const struct iee_security_context *ctx)
{
	unsigned int i;
	int result = 0;

	for (i = 0; i < ARRAY_SIZE(watched_syscalls); i++) {
		unsigned long entry;

		if (watched_syscalls[i] >= ctx->syscall_count)
			continue;
		entry = (unsigned long)READ_ONCE(ctx->syscalls[watched_syscalls[i]]);
		if (entry >= ctx->modules_start && entry < ctx->modules_end)
			result |= RK_SYSCALL;
	}
	return result;
}

static int __iee_code notrace
rkspotter_check(const struct iee_security_context *ctx)
{
	unsigned int budget = READ_ONCE(pages_per_irq);
	unsigned long addr = cursor;
	unsigned int remaining = budget;
	int result = 0;

	if (!ctx->module_lookup || ctx->modules_start >= ctx->modules_end ||
	    !IS_ALIGNED(ctx->modules_start, PAGE_SIZE) ||
	    !IS_ALIGNED(ctx->modules_end, PAGE_SIZE))
		return RK_INCOMPLETE;
	if (addr < ctx->modules_start || addr >= ctx->modules_end)
		addr = ctx->modules_start;

	/* Reuse a hit only inside this RCU section; retain just the next address. */
	while (remaining && addr < ctx->modules_end) {
		struct module *mod = ctx->module_lookup(addr);
		unsigned long next_addr = addr + PAGE_SIZE;
		unsigned int used = 1;

		if (mod)
			result |= rkspotter_inspect_region(ctx, mod, addr,
						   remaining, &used, &next_addr);
		remaining -= used;
		addr = next_addr;
	}
	if (addr >= ctx->modules_end) {
		result |= rkspotter_syscalls(ctx);
		WRITE_ONCE(scan_runs, READ_ONCE(scan_runs) + 1);
		addr = ctx->modules_start;
	}
	cursor = addr;
	WRITE_ONCE(findings, READ_ONCE(findings) | result);
	return result;
}

static const struct iee_security_ops rkspotter_ops = {
	.check = rkspotter_check,
};

static int __init rkspotter_init(void)
{
	unsigned int i;

	if (!pages_per_irq || pages_per_irq > RKSPOTTER_MAX_PAGES_PER_IRQ)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(suspicious_signatures); i++)
		if (!suspicious_signatures[i].len ||
		    suspicious_signatures[i].len > RKSPOTTER_SIG_MAX)
			return -EINVAL;
	return iee_security_register(&rkspotter_ops);
}

static void __exit rkspotter_exit(void)
{
	iee_security_unregister(&rkspotter_ops);
}

module_init(rkspotter_init);
module_exit(rkspotter_exit);

MODULE_AUTHOR("linuxthor; RISC-V IEE port");
MODULE_DESCRIPTION("Incremental IEE module-tree rootkit detector");
MODULE_LICENSE("GPL");

#endif /* CONFIG_IEE_RKSPOTTER */
