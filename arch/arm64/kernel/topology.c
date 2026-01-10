/*
 * arch/arm64/kernel/topology.c
 *
 * Copyright (C) 2011,2013,2014 Linaro Limited.
 *
 * Based on the arm32 version written by Vincent Guittot in turn based on
 * arch/sh/kernel/topology.c
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#include <linux/acpi.h>
#include <linux/arch_topology.h>
#include <linux/cacheinfo.h>
#include <linux/cpufreq.h>
#include <linux/init.h>
#include <linux/percpu.h>

#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/topology.h>
#include <asm/arch_timer.h>

#ifdef CONFIG_ACPI
static bool __init acpi_cpu_is_threaded(int cpu)
{
	int is_threaded = acpi_pptt_cpu_is_thread(cpu);

	/*
	 * if the PPTT doesn't have thread information, assume a homogeneous
	 * machine and return the current CPU's thread state.
	 */
	if (is_threaded < 0)
		is_threaded = read_cpuid_mpidr() & MPIDR_MT_BITMASK;

	return !!is_threaded;
}

/*
 * Propagate the topology information of the processor_topology_node tree to the
 * cpu_topology array.
 */
int __init parse_acpi_topology(void)
{
	int cpu, topology_id;

	if (acpi_disabled)
		return 0;

	for_each_possible_cpu(cpu) {
		topology_id = find_acpi_cpu_topology(cpu, 0);
		if (topology_id < 0)
			return topology_id;

		if (acpi_cpu_is_threaded(cpu)) {
			cpu_topology[cpu].thread_id = topology_id;
			topology_id = find_acpi_cpu_topology(cpu, 1);
			cpu_topology[cpu].core_id   = topology_id;
		} else {
			cpu_topology[cpu].thread_id  = -1;
			cpu_topology[cpu].core_id    = topology_id;
		}
		topology_id = find_acpi_cpu_topology_cluster(cpu);
		cpu_topology[cpu].cluster_id = topology_id;
		topology_id = find_acpi_cpu_topology_package(cpu);
		cpu_topology[cpu].package_id = topology_id;
	}

	return 0;
}
#endif

static unsigned int cpufreq_khz;

struct arch_cpufreq_sample {
	unsigned int khz;
	ktime_t time;
};

static DEFINE_PER_CPU(struct arch_cpufreq_sample, samples);

#define ARCH_CPUFREQ_CACHE_THRESHOLD_MS	100

static void arch_cpufreq_snapshot_cpu(int cpu, ktime_t now)
{
	s64 time_delta = ktime_ms_delta(now, per_cpu(samples.time, cpu));
	struct arch_cpufreq_sample *s;

	/* Don't bother re-computing within the cache threshold time. */
	if (time_delta < ARCH_CPUFREQ_CACHE_THRESHOLD_MS)
		return;

	s = per_cpu_ptr(&samples, cpu);

	s->khz = cpufreq_get(cpu);
	if (s->khz)
		s->time = ktime_get();
}

unsigned int arch_cpufreq_get_khz(int cpu)
{
	unsigned int new_cpufreq;

	arch_cpufreq_snapshot_cpu(cpu, ktime_get());

	new_cpufreq = per_cpu(samples.khz, cpu);

	/*
	 * If the cpufreq driver can provide a value, use it.
	 * Otherwise use the cpufreq_khz.
	 */
	return new_cpufreq ? new_cpufreq : cpufreq_khz;
}

#ifdef CONFIG_ARM64_AMU_EXTN
#define read_corecnt()	read_sysreg_s(SYS_AMEVCNTR0_CORE_EL0)
#define read_constcnt()	read_sysreg_s(SYS_AMEVCNTR0_CONST_EL0)
#else
#define read_corecnt()	(0UL)
#define read_constcnt()	(0UL)
#endif

#undef pr_fmt
#define pr_fmt(fmt) "AMU: " fmt
#define ARCH_FREQ_THRESHOLD_MS	10

static DEFINE_PER_CPU_READ_MOSTLY(unsigned long, arch_max_freq_scale);
static DEFINE_PER_CPU(u64, arch_const_cycles_prev);
static DEFINE_PER_CPU(u64, arch_core_cycles_prev);
static cpumask_var_t amu_fie_cpus;

/*
 * Sample cpu freq.
 *
 * The register SYS_AMEVCNTR0_EL0(1) increases at the fixed
 * rate of arch_timer_get_cntfrq() and can be used as timekeeper.
 * While The register SYS_AMEVCNTR0_EL0(0) counte the cpu
 * cycle elapsed. With the two registers, we can sample cpu
 * freq:
 *   delta(cycle) / delta(timekeeper)
 *
 * But these registers are halted by wfe/wfi and can't
 * in/out of the idle state synchronously, which is different
 * from x86 MSR_IA32_APERF/MSR_IA32_MPERF.
 *
 * NOTE:
 * ALL core use same freq by default(ignore big.LITTLE)
 */
static void __init __arch_cpufreq_init(void *dummy)
{
	unsigned long flags;
	u64 stable_cnt;
	u64 nonstable_cnt;
	u32 freq = arch_timer_get_cntfrq();
	u64 delta = freq / 1000 * ARCH_FREQ_THRESHOLD_MS;
	u64 counter;

	local_irq_save(flags);
	counter = stable_cnt = read_sysreg_s(SYS_AMEVCNTR0_EL0(1));
	nonstable_cnt = read_sysreg_s(SYS_AMEVCNTR0_EL0(0));
	local_irq_restore(flags);

	/*
	 * Meaningless operations & keep cpu out of
	 * wfe/wfi idle state.
	 *
	 * While sampling core freq, detecting time taking
	 * may be more than 10 miliseconds by default.
	 * REFER to: intel x86 APERFMPERF_CACHE_THRESHOLD_MS
	 */
	while (counter - stable_cnt < delta)
		counter = read_sysreg_s(SYS_AMEVCNTR0_EL0(1));

	local_irq_save(flags);
	stable_cnt = read_sysreg_s(SYS_AMEVCNTR0_EL0(1)) - stable_cnt;
	nonstable_cnt = read_sysreg_s(SYS_AMEVCNTR0_EL0(0)) - nonstable_cnt;
	local_irq_restore(flags);

	cpufreq_khz = div64_u64(freq * nonstable_cnt, stable_cnt) / 1000;
}

static int __init arch_cpufreq_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (cpu_has_amu_feat(cpu)) {
			smp_call_function_single(cpu, __arch_cpufreq_init, NULL, 1);
			return 0;
		}
	}
	return 0;
}

late_initcall(arch_cpufreq_init);

void update_freq_counters_refs(void)
{
	this_cpu_write(arch_core_cycles_prev, read_corecnt());
	this_cpu_write(arch_const_cycles_prev, read_constcnt());
}

static inline bool freq_counters_valid(int cpu)
{
	if ((cpu >= nr_cpu_ids) || !cpumask_test_cpu(cpu, cpu_present_mask))
		return false;

	if (!cpu_has_amu_feat(cpu)) {
		pr_debug("CPU%d: counters are not supported.\n", cpu);
		return false;
	}

	if (unlikely(!per_cpu(arch_const_cycles_prev, cpu) ||
		     !per_cpu(arch_core_cycles_prev, cpu))) {
		pr_debug("CPU%d: cycle counters are not enabled.\n", cpu);
		return false;
	}

	return true;
}

static int freq_inv_set_max_ratio(int cpu, u64 max_rate, u64 ref_rate)
{
	u64 ratio;

	if (unlikely(!max_rate || !ref_rate)) {
		pr_debug("CPU%d: invalid maximum or reference frequency.\n",
			 cpu);
		return -EINVAL;
	}

	/*
	 * Pre-compute the fixed ratio between the frequency of the constant
	 * reference counter and the maximum frequency of the CPU.
	 *
	 *			    ref_rate
	 * arch_max_freq_scale =   ---------- * SCHED_CAPACITY_SCALE²
	 *			    max_rate
	 *
	 * We use a factor of 2 * SCHED_CAPACITY_SHIFT -> SCHED_CAPACITY_SCALE²
	 * in order to ensure a good resolution for arch_max_freq_scale for
	 * very low reference frequencies (down to the KHz range which should
	 * be unlikely).
	 */
	ratio = ref_rate << (2 * SCHED_CAPACITY_SHIFT);
	ratio = div64_u64(ratio, max_rate);
	if (!ratio) {
		WARN_ONCE(1, "Reference frequency too low.\n");
		return -EINVAL;
	}

	per_cpu(arch_max_freq_scale, cpu) = (unsigned long)ratio;

	return 0;
}

static void amu_scale_freq_tick(void)
{
	u64 prev_core_cnt, prev_const_cnt;
	u64 core_cnt, const_cnt, scale;

	prev_const_cnt = this_cpu_read(arch_const_cycles_prev);
	prev_core_cnt = this_cpu_read(arch_core_cycles_prev);

	update_freq_counters_refs();

	const_cnt = this_cpu_read(arch_const_cycles_prev);
	core_cnt = this_cpu_read(arch_core_cycles_prev);

	if (unlikely(core_cnt <= prev_core_cnt ||
		     const_cnt <= prev_const_cnt))
		return;

	/*
	 *	    /\core    arch_max_freq_scale
	 * scale =  ------- * --------------------
	 *	    /\const   SCHED_CAPACITY_SCALE
	 *
	 * See validate_cpu_freq_invariance_counters() for details on
	 * arch_max_freq_scale and the use of SCHED_CAPACITY_SHIFT.
	 */
	scale = core_cnt - prev_core_cnt;
	scale *= this_cpu_read(arch_max_freq_scale);
	scale = div64_u64(scale >> SCHED_CAPACITY_SHIFT,
			  const_cnt - prev_const_cnt);

	scale = min_t(unsigned long, scale, SCHED_CAPACITY_SCALE);
	this_cpu_write(arch_freq_scale, (unsigned long)scale);
}

static struct scale_freq_data amu_sfd = {
	.source = SCALE_FREQ_SOURCE_ARCH,
	.set_freq_scale = amu_scale_freq_tick,
};

static void amu_fie_setup(const struct cpumask *cpus)
{
	int cpu;

	/* We are already set since the last insmod of cpufreq driver */
	if (unlikely(cpumask_subset(cpus, amu_fie_cpus)))
		return;

	for_each_cpu(cpu, cpus) {
		if (!freq_counters_valid(cpu) ||
		    freq_inv_set_max_ratio(cpu,
					   cpufreq_get_hw_max_freq(cpu) * 1000ULL,
					   arch_timer_get_rate()))
			return;
	}

	cpumask_or(amu_fie_cpus, amu_fie_cpus, cpus);

	topology_set_scale_freq_source(&amu_sfd, amu_fie_cpus);

	pr_debug("CPUs[%*pbl]: counters will be used for FIE.",
		 cpumask_pr_args(cpus));
}

static int init_amu_fie_callback(struct notifier_block *nb, unsigned long val,
				 void *data)
{
	struct cpufreq_policy *policy = data;

	if (val == CPUFREQ_CREATE_POLICY)
		amu_fie_setup(policy->related_cpus);

	/*
	 * We don't need to handle CPUFREQ_REMOVE_POLICY event as the AMU
	 * counters don't have any dependency on cpufreq driver once we have
	 * initialized AMU support and enabled invariance. The AMU counters will
	 * keep on working just fine in the absence of the cpufreq driver, and
	 * for the CPUs for which there are no counters available, the last set
	 * value of arch_freq_scale will remain valid as that is the frequency
	 * those CPUs are running at.
	 */

	return 0;
}

static struct notifier_block init_amu_fie_notifier = {
	.notifier_call = init_amu_fie_callback,
};

static int __init init_amu_fie(void)
{
	int ret;

	if (!zalloc_cpumask_var(&amu_fie_cpus, GFP_KERNEL))
		return -ENOMEM;

	ret = cpufreq_register_notifier(&init_amu_fie_notifier,
					CPUFREQ_POLICY_NOTIFIER);
	if (ret)
		free_cpumask_var(amu_fie_cpus);

	return ret;
}
core_initcall(init_amu_fie);

#ifdef CONFIG_ACPI_CPPC_LIB
#include <acpi/cppc_acpi.h>

static void cpu_read_corecnt(void *val)
{
	/*
	 * A value of 0 can be returned if the current CPU does not support AMUs
	 * or if the counter is disabled for this CPU. A return value of 0 at
	 * counter read is properly handled as an error case by the users of the
	 * counter.
	 */
	*(u64 *)val = read_corecnt();
}

static void cpu_read_constcnt(void *val)
{
	/*
	 * Return 0 if the current CPU is affected by erratum 2457168. A value
	 * of 0 is also returned if the current CPU does not support AMUs or if
	 * the counter is disabled. A return value of 0 at counter read is
	 * properly handled as an error case by the users of the counter.
	 */
	*(u64 *)val = this_cpu_has_cap(ARM64_WORKAROUND_2457168) ?
		      0UL : read_constcnt();
}

static inline
int counters_read_on_cpu(int cpu, smp_call_func_t func, u64 *val)
{
	/*
	 * Abort call on counterless CPU or when interrupts are
	 * disabled - can lead to deadlock in smp sync call.
	 */
	if (!cpu_has_amu_feat(cpu))
		return -EOPNOTSUPP;

	if (WARN_ON_ONCE(irqs_disabled()))
		return -EPERM;

	smp_call_function_single(cpu, func, val, 1);

	return 0;
}

/*
 * Refer to drivers/acpi/cppc_acpi.c for the description of the functions
 * below.
 */
bool cpc_ffh_supported(void)
{
	int cpu = get_cpu_with_amu_feat();

	/*
	 * FFH is considered supported if there is at least one present CPU that
	 * supports AMUs. Using FFH to read core and reference counters for CPUs
	 * that do not support AMUs, have counters disabled or that are affected
	 * by errata, will result in a return value of 0.
	 *
	 * This is done to allow any enabled and valid counters to be read
	 * through FFH, knowing that potentially returning 0 as counter value is
	 * properly handled by the users of these counters.
	 */
	if ((cpu >= nr_cpu_ids) || !cpumask_test_cpu(cpu, cpu_present_mask))
		return false;

	return true;
}

int cpc_read_ffh(int cpu, struct cpc_reg *reg, u64 *val)
{
	int ret = -EOPNOTSUPP;

	switch ((u64)reg->address) {
	case 0x0:
		ret = counters_read_on_cpu(cpu, cpu_read_corecnt, val);
		break;
	case 0x1:
		ret = counters_read_on_cpu(cpu, cpu_read_constcnt, val);
		break;
	}

	if (!ret) {
		*val &= GENMASK_ULL(reg->bit_offset + reg->bit_width - 1,
				    reg->bit_offset);
		*val >>= reg->bit_offset;
	}

	return ret;
}

int cpc_write_ffh(int cpunum, struct cpc_reg *reg, u64 val)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_ACPI_CPPC_LIB */
