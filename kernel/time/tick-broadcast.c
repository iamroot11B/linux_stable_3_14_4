/*
 * linux/kernel/time/tick-broadcast.c
 *
 * This file contains functions which emulate a local clock-event
 * device via a broadcast event source.
 *
 * Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 * Copyright(C) 2006-2007, Timesys Corp., Thomas Gleixner
 *
 * This code is licenced under the GPL version 2. For details see
 * kernel-base/COPYING.
 */
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/profile.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/module.h>

#include "tick-internal.h"

/*
 * Broadcast support for broken x86 hardware, where the local apic
 * timer stops in C3 state.
 */

static struct tick_device tick_broadcast_device;
static cpumask_var_t tick_broadcast_mask;
static cpumask_var_t tick_broadcast_on;
static cpumask_var_t tmpmask;
static DEFINE_RAW_SPINLOCK(tick_broadcast_lock);
static int tick_broadcast_force;

#ifdef CONFIG_TICK_ONESHOT
static void tick_broadcast_clear_oneshot(int cpu);
#else
static inline void tick_broadcast_clear_oneshot(int cpu) { }
#endif

/*
 * Debugging: see timer_list.c
 */
struct tick_device *tick_get_broadcast_device(void)
{
	return &tick_broadcast_device;
}

struct cpumask *tick_get_broadcast_mask(void)
{
	return tick_broadcast_mask;
}

/*
 * Start the device in periodic mode
 */
/*! 2016.11.05 study -ing */
static void tick_broadcast_start_periodic(struct clock_event_device *bc)
{
	if (bc)
		tick_setup_periodic(bc, 1);
}

/*
 * Check, if the device can be utilized as broadcast device:
 */
/*! 2016.11.05 study -ing */
static bool tick_check_broadcast_device(struct clock_event_device *curdev,
					struct clock_event_device *newdev)
{
	/*! newdev->features 를 보고 판단하거나,  */
	if ((newdev->features & CLOCK_EVT_FEAT_DUMMY) ||
	    (newdev->features & CLOCK_EVT_FEAT_PERCPU) ||
	    (newdev->features & CLOCK_EVT_FEAT_C3STOP))
		return false;

	/*! mode를 보고 판단  */
	if (tick_broadcast_device.mode == TICKDEV_MODE_ONESHOT &&
	    !(newdev->features & CLOCK_EVT_FEAT_ONESHOT))
		return false;

	/*! 마지막으로 rating 을 보고 판단  */
	return !curdev || newdev->rating > curdev->rating;
}

/*
 * Conditionally install/replace broadcast device
 */
/*! 2016.11.05 study -ing */
void tick_install_broadcast_device(struct clock_event_device *dev)
{
	struct clock_event_device *cur = tick_broadcast_device.evtdev;

	if (!tick_check_broadcast_device(cur, dev))
		return;

	/*! dev->owner가 live 상태가 아니면 리턴 */
	if (!try_module_get(dev->owner))
		return;

	clockevents_exchange_device(cur, dev);
	/*! cur이 있으면 event_handler를 noop(do nothing) 으로 바ㅂ군다. */
	if (cur)
		cur->event_handler = clockevents_handle_noop;
	tick_broadcast_device.evtdev = dev;
	/*! tick_broadcast_mask 가 모두 비어있으면 */
	if (!cpumask_empty(tick_broadcast_mask))
		tick_broadcast_start_periodic(dev);
	/*
	 * Inform all cpus about this. We might be in a situation
	 * where we did not switch to oneshot mode because the per cpu
	 * devices are affected by CLOCK_EVT_FEAT_C3STOP and the lack
	 * of a oneshot capable broadcast device. Without that
	 * notification the systems stays stuck in periodic mode
	 * forever.
	 */
	/*! ONESHOT 모드면  */
	if (dev->features & CLOCK_EVT_FEAT_ONESHOT)
		tick_clock_notify();
}

/*
 * Check, if the device is the broadcast device
 */
/*! 2016.11.05 study -ing  */
int tick_is_broadcast_device(struct clock_event_device *dev)
{
	return (dev && tick_broadcast_device.evtdev == dev);
}

static void err_broadcast(const struct cpumask *mask)
{
	pr_crit_once("Failed to broadcast timer tick. Some CPUs may be unresponsive.\n");
}

/*! 2016.11.05 study -ing */
static void tick_device_setup_broadcast_func(struct clock_event_device *dev)
{
	/*! dev->broadcast가 NULL 이면 tick_brocast로,
	 * tick_brocast도 NULL 이면 err_broadcast로 설정
	 */
	if (!dev->broadcast)
		dev->broadcast = tick_broadcast;
	if (!dev->broadcast) {
		pr_warn_once("%s depends on broadcast, but no broadcast function available\n",
			     dev->name);
		dev->broadcast = err_broadcast;
	}
}

/*
 * Check, if the device is disfunctional and a place holder, which
 * needs to be handled by the broadcast device.
 */
/*! 2016.11.05 study -ing  */
int tick_device_uses_broadcast(struct clock_event_device *dev, int cpu)
{
	struct clock_event_device *bc = tick_broadcast_device.evtdev;
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	/*
	 * Devices might be registered with both periodic and oneshot
	 * mode disabled. This signals, that the device needs to be
	 * operated from the broadcast device and is a placeholder for
	 * the cpu local device.
	 */
	/*! dev->features의 CLOCK_EVT_FEAT_DUMMY bit가 set 안되어있으면,
	 *  dev 는 functional 하다고 판단.
	 */
	if (!tick_device_is_functional(dev)) {
		/*! functional 하지 않으면,  */
		/*! 2016.11.05 study TBD  */
		/*! event_handler가 콜 될때 tick_handle_periodic을 자세히 보도록 한다.  */
		dev->event_handler = tick_handle_periodic;
		tick_device_setup_broadcast_func(dev);
		cpumask_set_cpu(cpu, tick_broadcast_mask);
		if (tick_broadcast_device.mode == TICKDEV_MODE_PERIODIC)
			tick_broadcast_start_periodic(bc);
		else
			tick_broadcast_setup_oneshot(bc);
		ret = 1;
	} else {
		/*
		 * Clear the broadcast bit for this cpu if the
		 * device is not power state affected.
		 */
		if (!(dev->features & CLOCK_EVT_FEAT_C3STOP))
			cpumask_clear_cpu(cpu, tick_broadcast_mask);
		else
			tick_device_setup_broadcast_func(dev);

		/*
		 * Clear the broadcast bit if the CPU is not in
		 * periodic broadcast on state.
		 */
		if (!cpumask_test_cpu(cpu, tick_broadcast_on))
			cpumask_clear_cpu(cpu, tick_broadcast_mask);

		/*! tick_broadcast_device.mode 의 각 모드별로,  */
		switch (tick_broadcast_device.mode) {
		case TICKDEV_MODE_ONESHOT:
			/*
			 * If the system is in oneshot mode we can
			 * unconditionally clear the oneshot mask bit,
			 * because the CPU is running and therefore
			 * not in an idle state which causes the power
			 * state affected device to stop. Let the
			 * caller initialize the device.
			 */
			/*! ONESHOT 모드면 clear onshot 수행  */
			tick_broadcast_clear_oneshot(cpu);
			ret = 0;
			break;

		case TICKDEV_MODE_PERIODIC:
			/*
			 * If the system is in periodic mode, check
			 * whether the broadcast device can be
			 * switched off now.
			 */
			/*! PERIODIC 모드이고 tick_broadcast_mask가 empty 이면,
			 *  shutodwn.
			 */
			if (cpumask_empty(tick_broadcast_mask) && bc)
				clockevents_shutdown(bc);
			/*
			 * If we kept the cpu in the broadcast mask,
			 * tell the caller to leave the per cpu device
			 * in shutdown state. The periodic interrupt
			 * is delivered by the broadcast device.
			 */
			/*! tick_broadcast_mask 에서 현재 cpu가 set 되어 있는지 확인   */
			ret = cpumask_test_cpu(cpu, tick_broadcast_mask);
			break;
		default:
			/* Nothing to do */
			ret = 0;
			break;
		}
	}
	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
	return ret;
}

#ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
int tick_receive_broadcast(void)
{
	struct tick_device *td = this_cpu_ptr(&tick_cpu_device);
	struct clock_event_device *evt = td->evtdev;

	if (!evt)
		return -ENODEV;

	if (!evt->event_handler)
		return -EINVAL;

	evt->event_handler(evt);
	return 0;
}
#endif

/*
 * Broadcast the event to the cpus, which are set in the mask (mangled).
 */
static void tick_do_broadcast(struct cpumask *mask)
{
	int cpu = smp_processor_id();
	struct tick_device *td;

	/*
	 * Check, if the current cpu is in the mask
	 */
	if (cpumask_test_cpu(cpu, mask)) {
		cpumask_clear_cpu(cpu, mask);
		td = &per_cpu(tick_cpu_device, cpu);
		td->evtdev->event_handler(td->evtdev);
	}

	if (!cpumask_empty(mask)) {
		/*
		 * It might be necessary to actually check whether the devices
		 * have different broadcast functions. For now, just use the
		 * one of the first device. This works as long as we have this
		 * misfeature only on x86 (lapic)
		 */
		td = &per_cpu(tick_cpu_device, cpumask_first(mask));
		td->evtdev->broadcast(mask);
	}
}

/*
 * Periodic broadcast:
 * - invoke the broadcast handlers
 */
static void tick_do_periodic_broadcast(void)
{
	raw_spin_lock(&tick_broadcast_lock);

	cpumask_and(tmpmask, cpu_online_mask, tick_broadcast_mask);
	tick_do_broadcast(tmpmask);

	raw_spin_unlock(&tick_broadcast_lock);
}

/*
 * Event handler for periodic broadcast ticks
 */
static void tick_handle_periodic_broadcast(struct clock_event_device *dev)
{
	ktime_t next;

	tick_do_periodic_broadcast();

	/*
	 * The device is in periodic mode. No reprogramming necessary:
	 */
	if (dev->mode == CLOCK_EVT_MODE_PERIODIC)
		return;

	/*
	 * Setup the next period for devices, which do not have
	 * periodic mode. We read dev->next_event first and add to it
	 * when the event already expired. clockevents_program_event()
	 * sets dev->next_event only when the event is really
	 * programmed to the device.
	 */
	for (next = dev->next_event; ;) {
		next = ktime_add(next, tick_period);

		if (!clockevents_program_event(dev, next, false))
			return;
		tick_do_periodic_broadcast();
	}
}

/*
 * Powerstate information: The system enters/leaves a state, where
 * affected devices might stop
 */
static void tick_do_broadcast_on_off(unsigned long *reason)
{
	struct clock_event_device *bc, *dev;
	struct tick_device *td;
	unsigned long flags;
	int cpu, bc_stopped;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	cpu = smp_processor_id();
	td = &per_cpu(tick_cpu_device, cpu);
	dev = td->evtdev;
	bc = tick_broadcast_device.evtdev;

	/*
	 * Is the device not affected by the powerstate ?
	 */
	if (!dev || !(dev->features & CLOCK_EVT_FEAT_C3STOP))
		goto out;

	if (!tick_device_is_functional(dev))
		goto out;

	bc_stopped = cpumask_empty(tick_broadcast_mask);

	switch (*reason) {
	case CLOCK_EVT_NOTIFY_BROADCAST_ON:
	case CLOCK_EVT_NOTIFY_BROADCAST_FORCE:
		cpumask_set_cpu(cpu, tick_broadcast_on);
		if (!cpumask_test_and_set_cpu(cpu, tick_broadcast_mask)) {
			if (tick_broadcast_device.mode ==
			    TICKDEV_MODE_PERIODIC)
				clockevents_shutdown(dev);
		}
		if (*reason == CLOCK_EVT_NOTIFY_BROADCAST_FORCE)
			tick_broadcast_force = 1;
		break;
	case CLOCK_EVT_NOTIFY_BROADCAST_OFF:
		if (tick_broadcast_force)
			break;
		cpumask_clear_cpu(cpu, tick_broadcast_on);
		if (!tick_device_is_functional(dev))
			break;
		if (cpumask_test_and_clear_cpu(cpu, tick_broadcast_mask)) {
			if (tick_broadcast_device.mode ==
			    TICKDEV_MODE_PERIODIC)
				tick_setup_periodic(dev, 0);
		}
		break;
	}

	if (cpumask_empty(tick_broadcast_mask)) {
		if (!bc_stopped)
			clockevents_shutdown(bc);
	} else if (bc_stopped) {
		if (tick_broadcast_device.mode == TICKDEV_MODE_PERIODIC)
			tick_broadcast_start_periodic(bc);
		else
			tick_broadcast_setup_oneshot(bc);
	}
out:
	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
}

/*
 * Powerstate information: The system enters/leaves a state, where
 * affected devices might stop.
 */
void tick_broadcast_on_off(unsigned long reason, int *oncpu)
{
	if (!cpumask_test_cpu(*oncpu, cpu_online_mask))
		printk(KERN_ERR "tick-broadcast: ignoring broadcast for "
		       "offline CPU #%d\n", *oncpu);
	else
		tick_do_broadcast_on_off(&reason);
}

/*
 * Set the periodic handler depending on broadcast on/off
 */
/*! 2016.11.05 study -ing */
void tick_set_periodic_handler(struct clock_event_device *dev, int broadcast)
{
	if (!broadcast)
		dev->event_handler = tick_handle_periodic;
	else
		dev->event_handler = tick_handle_periodic_broadcast;
}

/*
 * Remove a CPU from broadcasting
 */
void tick_shutdown_broadcast(unsigned int *cpup)
{
	struct clock_event_device *bc;
	unsigned long flags;
	unsigned int cpu = *cpup;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	bc = tick_broadcast_device.evtdev;
	cpumask_clear_cpu(cpu, tick_broadcast_mask);
	cpumask_clear_cpu(cpu, tick_broadcast_on);

	if (tick_broadcast_device.mode == TICKDEV_MODE_PERIODIC) {
		if (bc && cpumask_empty(tick_broadcast_mask))
			clockevents_shutdown(bc);
	}

	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
}

void tick_suspend_broadcast(void)
{
	struct clock_event_device *bc;
	unsigned long flags;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	bc = tick_broadcast_device.evtdev;
	if (bc)
		clockevents_shutdown(bc);

	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
}

int tick_resume_broadcast(void)
{
	struct clock_event_device *bc;
	unsigned long flags;
	int broadcast = 0;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	bc = tick_broadcast_device.evtdev;

	if (bc) {
		clockevents_set_mode(bc, CLOCK_EVT_MODE_RESUME);

		switch (tick_broadcast_device.mode) {
		case TICKDEV_MODE_PERIODIC:
			if (!cpumask_empty(tick_broadcast_mask))
				tick_broadcast_start_periodic(bc);
			broadcast = cpumask_test_cpu(smp_processor_id(),
						     tick_broadcast_mask);
			break;
		case TICKDEV_MODE_ONESHOT:
			if (!cpumask_empty(tick_broadcast_mask))
				broadcast = tick_resume_broadcast_oneshot(bc);
			break;
		}
	}
	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);

	return broadcast;
}


#ifdef CONFIG_TICK_ONESHOT

static cpumask_var_t tick_broadcast_oneshot_mask;
static cpumask_var_t tick_broadcast_pending_mask;
static cpumask_var_t tick_broadcast_force_mask;

/*
 * Exposed for debugging: see timer_list.c
 */
struct cpumask *tick_get_broadcast_oneshot_mask(void)
{
	return tick_broadcast_oneshot_mask;
}

/*
 * Called before going idle with interrupts disabled. Checks whether a
 * broadcast event from the other core is about to happen. We detected
 * that in tick_broadcast_oneshot_control(). The callsite can use this
 * to avoid a deep idle transition as we are about to get the
 * broadcast IPI right away.
 */
int tick_check_broadcast_expired(void)
{
	return cpumask_test_cpu(smp_processor_id(), tick_broadcast_force_mask);
}

/*
 * Set broadcast interrupt affinity
 */
/*! 2016.11.05 study -ing */
static void tick_broadcast_set_affinity(struct clock_event_device *bc,
					const struct cpumask *cpumask)
{
	/*! features를 보고 CLOCK_EVT_FEAT_DYNIRQ 가 아니면 리턴 */
	if (!(bc->features & CLOCK_EVT_FEAT_DYNIRQ))
		return;

	/*! bc->cpumask와 cpumask가 동일하면 리턴  */
	if (cpumask_equal(bc->cpumask, cpumask))
		return;

	/*! bc->cpumask 업데이트, irq affinity 업데이트 */
	bc->cpumask = cpumask;
	irq_set_affinity(bc->irq, bc->cpumask);
}
/*! 2016.11.05 study -ing */
static int tick_broadcast_set_event(struct clock_event_device *bc, int cpu,
				    ktime_t expires, int force)
{
	int ret;

	/*! ONESHOT 모드가 아니면  */
	if (bc->mode != CLOCK_EVT_MODE_ONESHOT)
		/*! ONESHOT 모드로 설정  */
		clockevents_set_mode(bc, CLOCK_EVT_MODE_ONESHOT);

	/*! bc dev를 expires 시간을 이용해 업데이트  */
	ret = clockevents_program_event(bc, expires, force);
	if (!ret)
		tick_broadcast_set_affinity(bc, cpumask_of(cpu));
	return ret;
}

int tick_resume_broadcast_oneshot(struct clock_event_device *bc)
{
	clockevents_set_mode(bc, CLOCK_EVT_MODE_ONESHOT);
	return 0;
}

/*
 * Called from irq_enter() when idle was interrupted to reenable the
 * per cpu device.
 */
void tick_check_oneshot_broadcast_this_cpu(void)
{
	if (cpumask_test_cpu(smp_processor_id(), tick_broadcast_oneshot_mask)) {
		struct tick_device *td = &__get_cpu_var(tick_cpu_device);

		/*
		 * We might be in the middle of switching over from
		 * periodic to oneshot. If the CPU has not yet
		 * switched over, leave the device alone.
		 */
		if (td->mode == TICKDEV_MODE_ONESHOT) {
			clockevents_set_mode(td->evtdev,
					     CLOCK_EVT_MODE_ONESHOT);
		}
	}
}

/*
 * Handle oneshot mode broadcasting
 */
static void tick_handle_oneshot_broadcast(struct clock_event_device *dev)
{
	struct tick_device *td;
	ktime_t now, next_event;
	int cpu, next_cpu = 0;

	raw_spin_lock(&tick_broadcast_lock);
again:
	dev->next_event.tv64 = KTIME_MAX;
	next_event.tv64 = KTIME_MAX;
	cpumask_clear(tmpmask);
	now = ktime_get();
	/* Find all expired events */
	for_each_cpu(cpu, tick_broadcast_oneshot_mask) {
		td = &per_cpu(tick_cpu_device, cpu);
		if (td->evtdev->next_event.tv64 <= now.tv64) {
			cpumask_set_cpu(cpu, tmpmask);
			/*
			 * Mark the remote cpu in the pending mask, so
			 * it can avoid reprogramming the cpu local
			 * timer in tick_broadcast_oneshot_control().
			 */
			cpumask_set_cpu(cpu, tick_broadcast_pending_mask);
		} else if (td->evtdev->next_event.tv64 < next_event.tv64) {
			next_event.tv64 = td->evtdev->next_event.tv64;
			next_cpu = cpu;
		}
	}

	/*
	 * Remove the current cpu from the pending mask. The event is
	 * delivered immediately in tick_do_broadcast() !
	 */
	cpumask_clear_cpu(smp_processor_id(), tick_broadcast_pending_mask);

	/* Take care of enforced broadcast requests */
	cpumask_or(tmpmask, tmpmask, tick_broadcast_force_mask);
	cpumask_clear(tick_broadcast_force_mask);

	/*
	 * Sanity check. Catch the case where we try to broadcast to
	 * offline cpus.
	 */
	if (WARN_ON_ONCE(!cpumask_subset(tmpmask, cpu_online_mask)))
		cpumask_and(tmpmask, tmpmask, cpu_online_mask);

	/*
	 * Wakeup the cpus which have an expired event.
	 */
	tick_do_broadcast(tmpmask);

	/*
	 * Two reasons for reprogram:
	 *
	 * - The global event did not expire any CPU local
	 * events. This happens in dyntick mode, as the maximum PIT
	 * delta is quite small.
	 *
	 * - There are pending events on sleeping CPUs which were not
	 * in the event mask
	 */
	if (next_event.tv64 != KTIME_MAX) {
		/*
		 * Rearm the broadcast device. If event expired,
		 * repeat the above
		 */
		if (tick_broadcast_set_event(dev, next_cpu, next_event, 0))
			goto again;
	}
	raw_spin_unlock(&tick_broadcast_lock);
}

/*
 * Powerstate information: The system enters/leaves a state, where
 * affected devices might stop
 */
void tick_broadcast_oneshot_control(unsigned long reason)
{
	struct clock_event_device *bc, *dev;
	struct tick_device *td;
	unsigned long flags;
	ktime_t now;
	int cpu;

	/*
	 * Periodic mode does not care about the enter/exit of power
	 * states
	 */
	if (tick_broadcast_device.mode == TICKDEV_MODE_PERIODIC)
		return;

	/*
	 * We are called with preemtion disabled from the depth of the
	 * idle code, so we can't be moved away.
	 */
	cpu = smp_processor_id();
	td = &per_cpu(tick_cpu_device, cpu);
	dev = td->evtdev;

	if (!(dev->features & CLOCK_EVT_FEAT_C3STOP))
		return;

	bc = tick_broadcast_device.evtdev;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);
	if (reason == CLOCK_EVT_NOTIFY_BROADCAST_ENTER) {
		if (!cpumask_test_and_set_cpu(cpu, tick_broadcast_oneshot_mask)) {
			WARN_ON_ONCE(cpumask_test_cpu(cpu, tick_broadcast_pending_mask));
			clockevents_set_mode(dev, CLOCK_EVT_MODE_SHUTDOWN);
			/*
			 * We only reprogram the broadcast timer if we
			 * did not mark ourself in the force mask and
			 * if the cpu local event is earlier than the
			 * broadcast event. If the current CPU is in
			 * the force mask, then we are going to be
			 * woken by the IPI right away.
			 */
			if (!cpumask_test_cpu(cpu, tick_broadcast_force_mask) &&
			    dev->next_event.tv64 < bc->next_event.tv64)
				tick_broadcast_set_event(bc, cpu, dev->next_event, 1);
		}
	} else {
		if (cpumask_test_and_clear_cpu(cpu, tick_broadcast_oneshot_mask)) {
			clockevents_set_mode(dev, CLOCK_EVT_MODE_ONESHOT);
			/*
			 * The cpu which was handling the broadcast
			 * timer marked this cpu in the broadcast
			 * pending mask and fired the broadcast
			 * IPI. So we are going to handle the expired
			 * event anyway via the broadcast IPI
			 * handler. No need to reprogram the timer
			 * with an already expired event.
			 */
			if (cpumask_test_and_clear_cpu(cpu,
				       tick_broadcast_pending_mask))
				goto out;

			/*
			 * Bail out if there is no next event.
			 */
			if (dev->next_event.tv64 == KTIME_MAX)
				goto out;
			/*
			 * If the pending bit is not set, then we are
			 * either the CPU handling the broadcast
			 * interrupt or we got woken by something else.
			 *
			 * We are not longer in the broadcast mask, so
			 * if the cpu local expiry time is already
			 * reached, we would reprogram the cpu local
			 * timer with an already expired event.
			 *
			 * This can lead to a ping-pong when we return
			 * to idle and therefor rearm the broadcast
			 * timer before the cpu local timer was able
			 * to fire. This happens because the forced
			 * reprogramming makes sure that the event
			 * will happen in the future and depending on
			 * the min_delta setting this might be far
			 * enough out that the ping-pong starts.
			 *
			 * If the cpu local next_event has expired
			 * then we know that the broadcast timer
			 * next_event has expired as well and
			 * broadcast is about to be handled. So we
			 * avoid reprogramming and enforce that the
			 * broadcast handler, which did not run yet,
			 * will invoke the cpu local handler.
			 *
			 * We cannot call the handler directly from
			 * here, because we might be in a NOHZ phase
			 * and we did not go through the irq_enter()
			 * nohz fixups.
			 */
			now = ktime_get();
			if (dev->next_event.tv64 <= now.tv64) {
				cpumask_set_cpu(cpu, tick_broadcast_force_mask);
				goto out;
			}
			/*
			 * We got woken by something else. Reprogram
			 * the cpu local timer device.
			 */
			tick_program_event(dev->next_event, 1);
		}
	}
out:
	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
}

/*
 * Reset the one shot broadcast for a cpu
 *
 * Called with tick_broadcast_lock held
 */
/*! 2016.11.05 study -ing */
static void tick_broadcast_clear_oneshot(int cpu)
{
	/*! 각 cpumask 클리어  */
	cpumask_clear_cpu(cpu, tick_broadcast_oneshot_mask);
	cpumask_clear_cpu(cpu, tick_broadcast_pending_mask);
}
/*! 2016.11.05 study -ing */
static void tick_broadcast_init_next_event(struct cpumask *mask,
					   ktime_t expires)
{
	struct tick_device *td;
	int cpu;

	/*! 모든 cpu loop 돌면서, */
	for_each_cpu(cpu, mask) {
		/*! 각 cpud의 td->evtdev->next_event를 expires로 업데이트 */
		td = &per_cpu(tick_cpu_device, cpu);
		if (td->evtdev)
			td->evtdev->next_event = expires;
	}
}

/**
 * tick_broadcast_setup_oneshot - setup the broadcast device
 */
/*! 2016.11.05 study -ing */
void tick_broadcast_setup_oneshot(struct clock_event_device *bc)
{
	int cpu = smp_processor_id();

	/* Set it up only once ! */
	/*! bc->event_handler를 tick_handle_oneshot_broadcast로 설정.(한번만 수행) */
	if (bc->event_handler != tick_handle_oneshot_broadcast) {
		int was_periodic = bc->mode == CLOCK_EVT_MODE_PERIODIC;

		bc->event_handler = tick_handle_oneshot_broadcast;

		/*
		 * We must be careful here. There might be other CPUs
		 * waiting for periodic broadcast. We need to set the
		 * oneshot_mask bits for those and program the
		 * broadcast device to fire.
		 */
		cpumask_copy(tmpmask, tick_broadcast_mask);
		cpumask_clear_cpu(cpu, tmpmask);
		/*! tick_broadcast_oneshot_mask와 tmpmask를 bit or 해서
		 *  tick_broadcast_oneshot_mask에 저장
		 */
		cpumask_or(tick_broadcast_oneshot_mask,
			   tick_broadcast_oneshot_mask, tmpmask);

		if (was_periodic && !cpumask_empty(tmpmask)) {
			clockevents_set_mode(bc, CLOCK_EVT_MODE_ONESHOT);
			tick_broadcast_init_next_event(tmpmask,
						       tick_next_period);
			tick_broadcast_set_event(bc, cpu, tick_next_period, 1);
		} else
			bc->next_event.tv64 = KTIME_MAX;
	} else {
		/*
		 * The first cpu which switches to oneshot mode sets
		 * the bit for all other cpus which are in the general
		 * (periodic) broadcast mask. So the bit is set and
		 * would prevent the first broadcast enter after this
		 * to program the bc device.
		 */
		tick_broadcast_clear_oneshot(cpu);
	}
}

/*
 * Select oneshot operating mode for the broadcast device
 */
void tick_broadcast_switch_to_oneshot(void)
{
	struct clock_event_device *bc;
	unsigned long flags;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	tick_broadcast_device.mode = TICKDEV_MODE_ONESHOT;
	bc = tick_broadcast_device.evtdev;
	if (bc)
		tick_broadcast_setup_oneshot(bc);

	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
}


/*
 * Remove a dead CPU from broadcasting
 */
void tick_shutdown_broadcast_oneshot(unsigned int *cpup)
{
	unsigned long flags;
	unsigned int cpu = *cpup;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	/*
	 * Clear the broadcast masks for the dead cpu, but do not stop
	 * the broadcast device!
	 */
	cpumask_clear_cpu(cpu, tick_broadcast_oneshot_mask);
	cpumask_clear_cpu(cpu, tick_broadcast_pending_mask);
	cpumask_clear_cpu(cpu, tick_broadcast_force_mask);

	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
}

/*
 * Check, whether the broadcast device is in one shot mode
 */
tick_handle_periodic
int tick_broadcast_oneshot_active(void)
{
	return tick_broadcast_device.mode == TICKDEV_MODE_ONESHOT;
}

/*
 * Check whether the broadcast device supports oneshot.
 */
bool tick_broadcast_oneshot_available(void)
{
	struct clock_event_device *bc = tick_broadcast_device.evtdev;

	return bc ? bc->features & CLOCK_EVT_FEAT_ONESHOT : false;
}

#endif
/*! 2016.10.15 study -ing */
void __init tick_broadcast_init(void)
{
	/*! 각 mask들 clear 수행  */
	zalloc_cpumask_var(&tick_broadcast_mask, GFP_NOWAIT);
	zalloc_cpumask_var(&tick_broadcast_on, GFP_NOWAIT);
	zalloc_cpumask_var(&tmpmask, GFP_NOWAIT);
#ifdef CONFIG_TICK_ONESHOT
	zalloc_cpumask_var(&tick_broadcast_oneshot_mask, GFP_NOWAIT);
	zalloc_cpumask_var(&tick_broadcast_pending_mask, GFP_NOWAIT);
	zalloc_cpumask_var(&tick_broadcast_force_mask, GFP_NOWAIT);
#endif
}
