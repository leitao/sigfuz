/*
 * Copyright 2018, Breno Leitao, Gustavo Romero, IBM Corp.
 * Licensed under GPLv2.
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

ucontext_t init_context, main_context;
static int count = 0;
static int first_time = 0;


/* checkpoint context */
ucontext_t *ckuc;

long long r(){
	long long f = rand();

	f = f<<32;
	f |= rand();

	return f;
}

int set_random(void *ptr, int chance, int bytes)
{
	long long v;
	if ((rand() % chance) == 0) {
		switch (bytes) {
			case 1:
				v = rand() %  UCHAR_MAX + 1;
				*(char *)ptr = v;
				break;
			case 2:
				v = rand() % USHRT_MAX + 1;
				*(short *)ptr = v;
				break;
			case 4:
				v = rand() % UINT_MAX + 1;
				*(int *)ptr = v;
				break;
			case 8:
				v = r();
				*(long long *)ptr = v;
				break;
			default:
				printf("Wrong value\n");
				exit(-1);
		}
		return 1;
	}

	return 0;
} 

int half_chance()
{
	return rand()%2;
}


int tenth_chance()
{
	return rand()%10 == 0;
}

#define STOP
void trap_signal_handler(int signo, siginfo_t *si, void *uc)
{
	ucontext_t *ucp = uc;

	ucp->uc_link = ckuc;

	printf("Rand = %lx\n", rand());

	/*  returns a garbase context 1/10 times */
	if (tenth_chance())
		memset(ucp->uc_link, rand(), sizeof(ucontext_t));
	else
		memcpy(ucp->uc_link, uc, sizeof(ucontext_t));

	/* Changing the checkpointed registers */
	if (half_chance())
		ucp->uc_link->uc_mcontext.gp_regs[PT_MSR] |= MSR_TS_S;
	else
		if (half_chance())
			ucp->uc_link->uc_mcontext.gp_regs[PT_MSR] |= MSR_TS_T;

	/* Checking the current register context */
	if (half_chance())
		ucp->uc_mcontext.gp_regs[PT_MSR] |= MSR_TS_S;
	else
		if (half_chance())
			ucp->uc_mcontext.gp_regs[PT_MSR] |= MSR_TS_T;


	/* 1/100 of the runs mess up with MSR */
	set_random(&ucp->uc_mcontext.gp_regs[PT_MSR], 100, 8);
	set_random(&ucp->uc_link->uc_mcontext.gp_regs[PT_MSR], 100, 8);

	set_random(&ucp->uc_mcontext.gp_regs[PT_NIP], 100, 8);
	set_random(&ucp->uc_link->uc_mcontext.gp_regs[PT_NIP], 100, 8);

	ucp->uc_mcontext.gp_regs[PT_TRAP] = r();
	ucp->uc_mcontext.gp_regs[PT_DSISR] = r();
	ucp->uc_mcontext.gp_regs[PT_DAR] = r();
	ucp->uc_mcontext.gp_regs[PT_ORIG_R3] = r();
	ucp->uc_mcontext.gp_regs[PT_XER] = r();
	ucp->uc_mcontext.gp_regs[PT_RESULT] = r();
	ucp->uc_mcontext.gp_regs[PT_SOFTE] = r();
	ucp->uc_mcontext.gp_regs[PT_DSCR] = r();
	ucp->uc_mcontext.gp_regs[PT_CTR] = r();
	ucp->uc_mcontext.gp_regs[PT_LNK] = r();
	ucp->uc_mcontext.gp_regs[PT_CCR] = r();
	ucp->uc_mcontext.gp_regs[PT_REGS_COUNT] = r();
	ucp->uc_mcontext.gp_regs[PT_VRSAVE] = r();
	ucp->uc_mcontext.gp_regs[PT_VSCR] = r();

	ucp->uc_link->uc_mcontext.gp_regs[PT_TRAP] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_DSISR] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_DAR] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_ORIG_R3] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_XER] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_RESULT] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_SOFTE] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_DSCR] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_CTR] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_LNK] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_CCR] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_REGS_COUNT] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_VRSAVE] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_VSCR] = r();

//	printf("NIP = %lx ", ucp->uc_link->uc_mcontext.gp_regs[PT_NIP]);
	printf(".");

	/*
	 * If the change above does not hit the bug, it will cause a
	 * segmentation fault, since the ck structures are NULL.
	 */
}

void seg_signal_handler(int signo, siginfo_t *si, void *uc)
{
	printf("Segv %d\n", count);

	exit(-1);

	if (count == COUNT_MAX) {
		setcontext(&main_context);
	}

	count++;
	setcontext(&init_context);
}


void tm_trap_test(void)
{
	struct sigaction trap_sa, seg_sa;
	int i = 0;

	ckuc = malloc(sizeof(ucontext_t));

	trap_sa.sa_flags = SA_SIGINFO;
	trap_sa.sa_sigaction = trap_signal_handler;

	seg_sa.sa_flags = SA_SIGINFO;
	seg_sa.sa_sigaction = seg_signal_handler;

	/* The signal handler will enable MSR_TS */
	sigaction(SIGUSR1, &trap_sa, NULL);

	/* If it does not crash, it will segfault, avoid it to retest */
	sigaction(SIGSEGV, &seg_sa, NULL);


	while ( i < COUNT_MAX) {
		pid_t t = fork();
		if (t == 0) {
			/* Once seed per process */
			srand(time(NULL) + getpid());
			raise(SIGUSR1);
			exit(0);
		} else {
			int ret;
			wait(&ret);
			//printf("Created pid = %d returned with %d\n", t, ret);
		}
#ifdef STOP
		i++;
#endif
	}

	free(ckuc);
	/* Should never hit this return */
	return;
}

static int first_time;

int tm_signal_force_msr(void)
{
	/* Will get back here after COUNT_MAX interactions */
	getcontext(&main_context);

	if (!first_time++)
		tm_trap_test();

	return 0;
}

int main(int argc, char **argv)
{
	tm_signal_force_msr();
}
