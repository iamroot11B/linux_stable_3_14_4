#ifndef _LINUX_IRQNR_H
#define _LINUX_IRQNR_H

#include <uapi/linux/irqnr.h>


extern int nr_irqs;
extern struct irq_desc *irq_to_desc(unsigned int irq);
unsigned int irq_get_next_irq(unsigned int offset);
/*! 2017. 8.12 study -ing */
# define for_each_irq_desc(irq, desc)					\
	for (irq = 0, desc = irq_to_desc(irq); irq < nr_irqs;		\
	     irq++, desc = irq_to_desc(irq))				\
		if (!desc)						\
			;						\
		else


# define for_each_irq_desc_reverse(irq, desc)				\
	for (irq = nr_irqs - 1, desc = irq_to_desc(irq); irq >= 0;	\
	     irq--, desc = irq_to_desc(irq))				\
		if (!desc)						\
			;						\
		else

#ifdef CONFIG_SMP
#define irq_node(irq)	(irq_get_irq_data(irq)->node)
#else
#define irq_node(irq)	0
#endif

# define for_each_active_irq(irq)			\
	for (irq = irq_get_next_irq(0); irq < nr_irqs;	\
	     irq = irq_get_next_irq(irq + 1))

#define for_each_irq_nr(irq)                   \
       for (irq = 0; irq < nr_irqs; irq++)

#endif
