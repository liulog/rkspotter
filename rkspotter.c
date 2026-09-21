// SPDX-License-Identifier: GPL-2.0
/*
 * rkspotter - RISC-V/Linux 6.x port of the rootkit-spotter module.
 *
 * The original detector walked the module virtual-address range looking for
 * modules that had disappeared from the public module list.  Keep that model,
 * but use the split module-memory layout introduced in Linux 6.4 and execute
 * the scan through the common IEE security-tool interface.
 */

#include <linux/iee_security.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/poison.h>
#include <linux/sizes.h>
#include <linux/string.h>

typedef struct module *(*module_address_fn_t)(unsigned long addr);

static module_address_fn_t module_address_fn;
static unsigned long scan_runs;
static unsigned long suspect_modules;

struct encoded_signature {
	const u8 *data;
	u8 len;
};

static const u8 signature_0[] = {
	0x8a, 0xd7, 0xc0, 0xd5, 0xd1, 0xcc, 0xc9, 0xc0, 0x8a, 0xd7, 0xc0, 0xd5, 0xd1, 0xcc, 0xc9, 0xc0,
};
static const u8 signature_1[] = {
	0xee, 0xed, 0xea, 0xea, 0xee, 0xfa,
};
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
static const u8 signature_6[] = {
	0xe2, 0xcc, 0xd3, 0xcc, 0xcb, 0xc2, 0x85, 0xd7, 0x95, 0x95, 0xd1,
};
static const u8 signature_7[] = {
	0xe0, 0xdd, 0xc4, 0xc8, 0xd5, 0xc9, 0xc0, 0x85, 0xf7, 0xca, 0xca, 0xd1, 0xce, 0xcc, 0xd1,
};
static const u8 signature_8[] = {
	0xc2, 0xcc, 0xd3, 0xc0, 0xc8, 0xc0, 0xd7, 0xca, 0xca, 0xd1,
};
static const u8 signature_9[] = {
	0xc9, 0xcc, 0xc9, 0xdc, 0xca, 0xc3, 0xd1, 0xcd, 0xc0, 0xd3, 0xc4, 0xc9, 0xc9, 0xc0, 0xdc,
};
static const u8 signature_10[] = {
	0xc1, 0xcc, 0xc4, 0xc8, 0xca, 0xd7, 0xd5, 0xcd, 0xcc, 0xcb, 0xc0, 0xfa,
};
static const u8 signature_11[] = {
	0xe9, 0xee, 0xe8, 0x85, 0xd7, 0xca, 0xca, 0xd1, 0xce, 0xcc, 0xd1,
};
static const u8 signature_12[] = {
	0xfa, 0xc7, 0xc4, 0xc6, 0xce, 0xc1, 0xca, 0xca, 0xd7, 0xfa, 0xd0, 0xd6, 0xc0, 0xd7,
};
static const u8 signature_13[] = {
	0x8a, 0xc0, 0xd1, 0xc6, 0x8a, 0xd6, 0xc0, 0xc6, 0xd7, 0xc0, 0xd1, 0xd6, 0xcd, 0xc4, 0xc1, 0xca, 0xd2,
};
static const u8 signature_14[] = {
	0xcd, 0xcc, 0xc1, 0xc0, 0x85, 0xd5, 0xcc, 0xc1, 0x85, 0xc6, 0xca, 0xc8, 0xc8, 0xc4, 0xcb, 0xc1,
};
static const u8 signature_15[] = {
	0xc8, 0xca, 0xc1, 0xd0, 0xc9, 0xc0, 0xfa, 0xcd, 0xcc, 0xc1, 0xc0,
};
static const u8 signature_16[] = {
	0xd7, 0x95, 0x95, 0xd1, 0xce, 0xcc, 0xd1,
};
static const u8 signature_17[] = {
	0xd7, 0x95, 0x95, 0xd1, 0xce, 0x94, 0xd1,
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
};

static void decode_signature(const struct encoded_signature *encoded,
			     char *decoded)
{
	int i;

	for (i = 0; i < encoded->len; i++)
		decoded[i] = encoded->data[i] ^ 0xa5;
	decoded[encoded->len] = '\0';
}

static void *rkspotter_resolve(const char *name)
{
	struct kprobe probe = { .symbol_name = name };
	void *address;

	if (register_kprobe(&probe))
		return NULL;
	address = probe.addr;
	unregister_kprobe(&probe);
	return address;
}

static bool rkspotter_mem_contains(const void *base, size_t size,
				   const char *needle)
{
	size_t needle_len = strlen(needle);
	const u8 *memory = base;
	size_t offset;

	if (!base || needle_len > size)
		return false;

	for (offset = 0; offset + needle_len <= size; offset++) {
		char sample[64];

		if (needle_len > sizeof(sample))
			return false;
		if (!copy_from_kernel_nofault(sample, memory + offset, needle_len) &&
		    !memcmp(sample, needle, needle_len))
			return true;
	}
	return false;
}

static bool rkspotter_check_module(struct module *mod)
{
	bool suspect = false;
	int i;

	if (READ_ONCE(mod->list.next) == LIST_POISON1 ||
	    READ_ONCE(mod->list.prev) == LIST_POISON2 ||
	    READ_ONCE(mod->list.next) == READ_ONCE(mod->list.prev)) {
		pr_warn("rkspotter: module %s has suspicious list links\n", mod->name);
		suspect = true;
	}
	if (!mod->mkobj.kobj.state_in_sysfs) {
		pr_warn("rkspotter: module %s is absent from sysfs\n", mod->name);
		suspect = true;
	}

	for (i = 0; i < ARRAY_SIZE(suspicious_signatures); i++) {
		char signature[64];

		decode_signature(&suspicious_signatures[i], signature);
		if (rkspotter_mem_contains(mod->mem[MOD_RODATA].base,
					  mod->mem[MOD_RODATA].size,
					  signature) ||
		    rkspotter_mem_contains(mod->mem[MOD_DATA].base,
					  mod->mem[MOD_DATA].size,
					  signature)) {
			pr_warn("rkspotter: module %s contains signature %s\n",
				mod->name, signature);
			suspect = true;
			break;
		}
	}
	return suspect;
}

static unsigned long rkspotter_scan(void)
{
	struct module *last = NULL;
	unsigned long address;
	unsigned long modules_start;
	unsigned long modules_end;

	modules_start = ALIGN_DOWN((unsigned long)THIS_MODULE->mem[MOD_TEXT].base,
				   SZ_2G);
	modules_end = modules_start + SZ_2G;
	for (address = modules_start; address < modules_end; address += PAGE_SIZE) {
		struct module *mod = module_address_fn(address);

		if (!mod || mod == last)
			continue;
		last = mod;
		if (mod != THIS_MODULE && rkspotter_check_module(mod))
			suspect_modules++;
	}
	scan_runs++;
	return suspect_modules;
}

static unsigned long rkspotter_iee_callback(enum iee_security_tool_id id,
		enum iee_security_reason reason, unsigned long event, void *context)
{
	if (id != IEE_SECURITY_TOOL_RKSPOTTER ||
	    reason != IEE_SECURITY_REASON_CALLBACK || event)
		return -EINVAL;
	return 0;
}

static int __init rkspotter_init(void)
{
	unsigned long result;
	int ret;

	module_address_fn = rkspotter_resolve("__module_address");
	if (!module_address_fn)
		return -ENOENT;

	ret = iee_security_tool_register(IEE_SECURITY_TOOL_RKSPOTTER,
			IEE_SECURITY_TOOL_CALLBACK, 0, rkspotter_iee_callback,
			THIS_MODULE);
	if (ret)
		return ret;

	result = iee_security_tool_invoke(IEE_SECURITY_TOOL_RKSPOTTER, 0, NULL);
	if ((long)result < 0) {
		iee_security_tool_unregister(IEE_SECURITY_TOOL_RKSPOTTER,
					     rkspotter_iee_callback);
		return result;
	}
	/* The address-space walk may fault and therefore runs after IEE returns. */
	result = rkspotter_scan();
	pr_info("rkspotter: IEE-authorized scan complete, suspects=%lu\n", result);
	return 0;
}

static void __exit rkspotter_exit(void)
{
	iee_security_tool_unregister(IEE_SECURITY_TOOL_RKSPOTTER,
				     rkspotter_iee_callback);
	pr_info("rkspotter: unloaded, scans=%lu suspects=%lu\n",
		scan_runs, suspect_modules);
}

module_init(rkspotter_init);
module_exit(rkspotter_exit);

MODULE_AUTHOR("linuxthor; RISC-V IEE port");
MODULE_DESCRIPTION("IEE-backed hidden and suspicious module detector");
MODULE_LICENSE("GPL");
