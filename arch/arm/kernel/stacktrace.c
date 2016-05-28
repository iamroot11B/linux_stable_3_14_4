#include <linux/export.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>

#include <asm/stacktrace.h>

#if defined(CONFIG_FRAME_POINTER) && !defined(CONFIG_ARM_UNWIND)
/*
 * Unwind the current stack frame and store the new register values in the
 * structure passed as argument. Unwinding is equivalent to a function return,
 * hence the new PC value rather than LR should be used for backtrace.
 *
 * With framepointer enabled, a simple function prologue looks like this:
 *	mov	ip, sp
 *	stmdb	sp!, {fp, ip, lr, pc}
 *	sub	fp, ip, #4
 *
 * A simple function epilogue looks like this:
 *	ldm	sp, {fp, sp, pc}
 *
 * Note that with framepointer enabled, even the leaf functions have the same
 * prologue and epilogue, therefore we can ignore the LR value in this case.
 */
/*! 2016-05-28 study -ing */
/*! frame을 한 단계 전 stack으로 unwind 시킴 - issue 2016-05-28 그림 참고 */
int notrace unwind_frame(struct stackframe *frame)
{
	unsigned long high, low;
	unsigned long fp = frame->fp;

	/*! fp가 thread 내에 있는지 (valid인지) 검사 */
	/* only go to a higher address on the stack */
	low = frame->sp;
	high = ALIGN(low, THREAD_SIZE);

	/* check current frame pointer is within bounds */
	if (fp < low + 12 || fp > high - 4)
		return -EINVAL;
	/*! 검사 끝 */

	/*! frame을 unwind 시킴 */
	/* restore the registers from the stack frame */
	frame->fp = *(unsigned long *)(fp - 12);
	frame->sp = *(unsigned long *)(fp - 8);
	frame->pc = *(unsigned long *)(fp - 4);

	return 0;
}
#endif

/*! 2016-05-28 study -ing */
/*! stackframe을 최근부터 따라가면서, stack trace에 저장함 */
void notrace walk_stackframe(struct stackframe *frame,
		     int (*fn)(struct stackframe *, void *), void *data)
{
	while (1) {
		int ret;

		/*! save_stack_trace_tsk()는 save_trace 전달 */
		if (fn(frame, data))
			break;
		/*! frame unwind 실패하면 break */
		ret = unwind_frame(frame);
		if (ret < 0)
			break;
	}
}
EXPORT_SYMBOL(walk_stackframe);

#ifdef CONFIG_STACKTRACE
struct stack_trace_data {
	struct stack_trace *trace;
	unsigned int no_sched_functions;
	unsigned int skip;
};

/*! 2016-05-28 study -ing */
static int save_trace(struct stackframe *frame, void *d)
{
	struct stack_trace_data *data = d;
	struct stack_trace *trace = data->trace;
	unsigned long addr = frame->pc;

	/*! sched_func 또는 lock_func이면 저장 안함 */
	if (data->no_sched_functions && in_sched_functions(addr))
		return 0;
	/*! stack 안할 갯수 확인 */
	if (data->skip) {
		data->skip--;
		return 0;
	}

	/*! stack trace에 호출한 함수 저장 */
	trace->entries[trace->nr_entries++] = addr;

	/*! 최대 stack trace 갯수에 도달하면 true */
	return trace->nr_entries >= trace->max_entries;
}

/*! 2016-05-28 study -ing */
void save_stack_trace_tsk(struct task_struct *tsk, struct stack_trace *trace)
{
	struct stack_trace_data data;
	struct stackframe frame;

	data.trace = trace;
	data.skip = trace->skip;

	if (tsk != current) {
#ifdef CONFIG_SMP
		/*
		 * What guarantees do we have here that 'tsk' is not
		 * running on another CPU?  For now, ignore it as we
		 * can't guarantee we won't explode.
		 */
		if (trace->nr_entries < trace->max_entries)
			/*! ULONG_MAX는 entires 배열에서 마지막을 의미 */
			trace->entries[trace->nr_entries++] = ULONG_MAX;
		return;
#else
		/*! smp가 아니면, frame 정보를 수동 입력 */
		data.no_sched_functions = 1;
		/*! task_thread_info -> cpu_context 에서 레지스터의 값을 가져옴 */
		frame.fp = thread_saved_fp(tsk);
		frame.sp = thread_saved_sp(tsk);
		frame.lr = 0;		/* recovered from the stack */
		frame.pc = thread_saved_pc(tsk);
#endif
	} else {
		register unsigned long current_sp asm ("sp");

		data.no_sched_functions = 0;
		/*! 현재 thread의 정보를 frame에 저장 */
		frame.fp = (unsigned long)__builtin_frame_address(0);
		frame.sp = current_sp;
		frame.lr = (unsigned long)__builtin_return_address(0);
		frame.pc = (unsigned long)save_stack_trace_tsk;
	}

	walk_stackframe(&frame, save_trace, &data);
	if (trace->nr_entries < trace->max_entries)
		/*! ULONG_MAX는 entires 배열에서 마지막을 의미 */
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}

/*! 2016-05-28 study -ing */
void save_stack_trace(struct stack_trace *trace)
{
	/*! current는 current thread info의 task_struct를 리턴함 */
	save_stack_trace_tsk(current, trace);
}
EXPORT_SYMBOL_GPL(save_stack_trace);
#endif
