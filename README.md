# Rootkit Spotter: incremental RISC-V IEE port

This port retains rkspotter's kernel module anomaly checks and its 24 encoded
rootkit data signatures. It targets the sibling `linux-riscv-security-tool`
kernel. The purpose is initial compatibility and IRQ/IEE overhead evaluation,
not complete rootkit detection or recovery from corrupt kernel memory.

## Configuration and loading

Select `CONFIG_IEE_RKSPOTTER=y` in the matching kernel. This automatically
enables hidden `CONFIG_IEE_SECURITY_TOOLS` for the shared IRQ/mapping adapter.
It does not require `CONFIG_IEE_ANTI_ROOTKIT`. The three tool options, including
`CONFIG_IEE_RKBREAKER`, are mutually exclusive. The default
`CONFIG_IEE_SECURITY_NONE` (Disabled) selection compiles out the integration. `CONFIG_MODULES_TREE_LOOKUP=y` is required; there
is no list fallback. PREEMPT_RT, memory hotplug and debug page allocation are
excluded. SWMMU and CSRRSI use the normal gate. No defconfig is modified here.

The Makefile is an external Kbuild file. From this directory, build against the
matching configured/built kernel using the usual external-module invocation:

```sh
make -C ../linux-riscv-security-tool M="$PWD" ARCH=riscv \
    CROSS_COMPILE=riscv64-unknown-linux-gnu- modules
# At runtime on the matching kernel:
insmod rkspotter.ko pages_per_irq=64
```

`pages_per_irq` defaults to 64, accepts 1..64 and cannot be changed through
sysfs after loading. Use the shared build script to select this tool and compare enabled/disabled
kernels from `k3_bianbu_defconfig`:

```sh
TOOL=rkspotter bash scripts/build-anti-rootkit-ab.sh both
```

Run that script from the kernel repository. `on` and `off` are also supported.
It toggles this tool, its common adapter and the Disabled choice, keeps
anti_rootkit and rkbreaker disabled, and
builds the external module only for `on`. The module must be rebuilt against
the matching kernel configuration and `include/linux/iee_security.h`.

One selected tool may register; a second registration returns `-EBUSY`. Each
hardware IRQ attempts one gate call for the registered tool. The shared kset
lock serializes successful checks across CPUs. A busy lock skips an attempt
without advancing the cursor. No periodic thread is created.

## Incremental scan and checks

Each successful hardware IRQ uses at most `pages_per_irq` pages of work (default
and maximum 64) in the actual `[MODULES_VADDR, MODULES_END)` range. A lookup miss
advances one page and consumes one budget page. A hit identifies the containing
core `module_memory` region from the returned module's current `mem[]` entries.
Metadata is checked once for that hit. Text and the checker's own regions consume
one budget page, then jump directly to `ALIGN(base + size, PAGE_SIZE)`. Other core data
regions are signature-scanned up to their end or the remaining page budget,
whichever comes first. Completing a region advances directly past it; a larger
data region resumes at the next unscanned page on a subsequent IRQ.

The first address of each such step gets a lookup inside IEE, using `mod_tree`'s
latched RB-tree and the adapter's RCU read lock. Consecutive data pages in the
same region reuse that hit only within the current IRQ/RCU section.
The numeric candidate address itself is never dereferenced by the lookup.
Holes are skipped, and only a live module's core regions are returned. Lookup
retries and tree depth are bounded; concurrent updates may cause a transient
miss that can be revisited on a later complete pass.

Only a scalar address cursor survives the interrupt. There is no saved target
module pointer, copied module list, target reference pin, or stale data buffer.
For each region hit, the checker performs:

- List metadata checks: poisoned list links or equal links indicative of unlinking.
  Equal links pointing at the ordinary list head are allowed for a sole module.
- Sysfs presence: the module kobject's `state_in_sysfs` must be set.
- Section metadata: with `CONFIG_KALLSYMS`, a cleared `sect_attrs` is suspicious.
  An absent `notes_attrs` alone is normal for modules without ELF notes.
- Known data signatures: scan MOD_DATA, MOD_RODATA or MOD_RO_AFTER_INIT in
  page-sized chunks within the remaining budget. Each chunk has a maximum
  31-byte look-ahead inside the same region to catch cross-page signatures.
  The checker skips its own data. It never reads module text, init regions,
  or address-space holes.

Finishing a full address-window pass additionally checks native `openat`,
`getdents64` and `readlinkat` table entries for targets in the module window.
It does not execute the targets. Every data-page scan, metadata read and
syscall comparison runs inside IEE.

Skipping is limited to the current region, so separately allocated regions of
the same module are still visited. A long region is split across IRQs; the next
IRQ performs a fresh lookup and repeats metadata checks before resuming, so no
module pointer survives an RCU section. A 64-page limit bounds page checks and
data chunks, not the virtual distance covered when a region is skipped. There
is no x86 CR0 instruction signature, process-environment scan,
`/etc/ld.so.preload` check, logging or remediation in this initial port. Those
userspace checks are not part of the IRQ-safe scan.

## Shared kernel API

Both tool ports use `struct iee_security_ops` with `check(ctx)`, declared in
`include/linux/iee_security.h`. This port calls `iee_security_register()` and
`iee_security_unregister()`; `iee_security_check()` exposes the same selected
checker for explicit measurement calls. The obsolete `.interrupt` interface,
kprobes and runtime symbol lookup are not used.

Both configurations use one common module-region mapping implementation.
It copies missing directory entries from `swapper_pg_dir` before modules become
visible, sharing the lower tables. There is no per-tool shadow copy or separate
construction of module payload mappings.

## Results and limits

Read-only module parameters expose `scan_runs` (complete address-window passes)
and `findings` (accumulated bits in hexadecimal). They are read from normal
kernel context; the IRQ/IEE path never prints findings, including at unload.

| Bit | Meaning |
| --- | --- |
| 0x01 | Suspicious module list links |
| 0x02 | Missing sysfs presence |
| 0x04 | Missing section attributes |
| 0x08 | Known data signature |
| 0x10 | Watched syscall points into the module window |
| 0x20 | Invalid bounds/incomplete inspection |

The common adapter synchronizes mappings before modules enter the visible list
and address tree. RCU delays module memory reclamation, and a non-blocking kset
lock stabilizes sysfs entries. Unregistration waits for RCU readers before the
checker is freed. No mutex, allocation, file access, mapping update, nested
gate call or exception-based probe is used in the scan.

The scan assumes valid tree/list pointers and normal loader/unloader lifetimes.
Deleting a module from the address tree evades this enumeration. Metadata
heuristics and signatures can produce false positives. A pass is not an atomic
snapshot and may miss a module loaded after its addresses were passed. RCU and
bounded loops do not make arbitrary pointer corruption safe or guarantee that
page faults are impossible. Interrupt masking and lock contention can delay
progress; IRQ latency still grows with the configured page budget and matches.
