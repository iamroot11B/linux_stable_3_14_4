#include <linux/init_task.h>
#include <linux/export.h>
#include <linux/mqueue.h>
#include <linux/sched.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/rt.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>

#include <asm/pgtable.h>
#include <asm/uaccess.h>

static struct signal_struct init_signals = INIT_SIGNALS(init_signals);
static struct sighand_struct init_sighand = INIT_SIGHAND(init_sighand);

/* Initial task structure */
/*! */
struct task_struct init_task = INIT_TASK(init_task);
EXPORT_SYMBOL(init_task);

/*
 * Initial thread structure. Alignment of this is handled by a special
 * linker map entry.
 */
/*!
 * 커널은 모든 아키텍쳐에서 공통적으로 사용되는 init_thread_union 이라는 task 를 사용하게 됩니다.
 * 아래 init_thread_union을 생성할 때 .data..init_task 섹션에 생성한다. 해당 섹션은 
 * arch/arm/kernel/vmlinux.lds.S 의 INIT_TASK_DATA(THREAD_SIZE)을 참고 (data섹션 시작부분)
 *
 * 참고: http://forum.falinux.com/zbxe/index.php?document_srl=551428&mid=lecture_tip
 * current 매크로 설명: http://www.iamroot.org/xe/index.php?mid=FreeBoard&document_srl=221745&act=dispBoardReplyComment&comment_srl=221937
 */
/*! #define __init_task_data __attribute__((__section__(".data..init_task"))) */
union thread_union init_thread_union __init_task_data =
	{ INIT_THREAD_INFO(init_task) };
