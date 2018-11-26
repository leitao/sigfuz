/*
 * Copyright 2018, Breno Leitao, IBM Corp.
 * Licensed under GPLv2.
 *
 * This is a Powerpc signal fuzzer. Where the output means:
 *
 * '.' An random context was generated
 * '!' A segmentation fault happened
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <limits.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <ucontext.h>

#define MSR_TS_S_LG     33              /* Trans Mem state: Suspended */
#define MSR_TS_T_LG     34              /* Trans Mem state: Active */
#define __MASK(X)       (1UL<<(X))
#define MSR_TM          __MASK(MSR_TM_LG)       /* Transactional Mem Available */
#define MSR_TS_S        __MASK(MSR_TS_S_LG)     /*  Transaction Suspended */
#define MSR_TS_T        __MASK(MSR_TS_T_LG)     /*  Transaction Suspended */
#define COUNT_MAX       1000		/* Number of interactions */

static int count = 0;
static int first_time = 0;

/* Should be an argument. TODO */
//#define STOP


/* checkpoint context */
ucontext_t *ckuc;

void mess_with_tm()
{
	if (1) {
		asm ("tbegin.	;"
		     "beq 8	;");
		asm("tsuspend.	;");
	}
}

void trap_signal_handler(int signo, siginfo_t *si, void *uc)
{
	ucontext_t *ucp = uc;

	ucp->uc_link = ckuc;

	memcpy(ucp->uc_link, uc, sizeof(ucontext_t));

	ucp->uc_link->uc_mcontext.gp_regs[PT_MSR] &=  ~MSR_TS_S;
	ucp->uc_link->uc_mcontext.gp_regs[PT_MSR] &= ~MSR_TS_T;
	ucp->uc_mcontext.gp_regs[PT_MSR] &=  ~MSR_TS_S;
	ucp->uc_mcontext.gp_regs[PT_MSR] &= ~MSR_TS_T;

	/* 1/100 of the runs mess up with MSR */

	printf("%lx %lx\n", ucp->uc_mcontext.gp_regs[PT_MSR], ucp->uc_link->uc_mcontext.gp_regs[PT_MSR]);
	mess_with_tm();
}

void tm_trap_test(void)
{
	struct sigaction trap_sa;

	ckuc = malloc(sizeof(ucontext_t));

	trap_sa.sa_flags = SA_SIGINFO;
	trap_sa.sa_sigaction = trap_signal_handler;

	/* The signal handler will enable MSR_TS */
	sigaction(SIGUSR1, &trap_sa, NULL);

	mess_with_tm();
	raise(SIGUSR1);

	free(ckuc);
	return;
}

int tm_signal_force_msr(void)
{

	tm_trap_test();

	return 0;
}

int main(int argc, char **argv)
{
	tm_signal_force_msr();
}
