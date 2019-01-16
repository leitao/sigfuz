/*
 * Copyright 2018, Breno Leitao, IBM Corp.
 * Licensed under GPLv2.
 *
 * This is a Powerpc signal fuzzer.
 */

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
#include <sys/mman.h>
#include <pthread.h>

#define MSR_TS_S_LG     33              /* Trans Mem state: Suspended */
#define MSR_TS_T_LG     34              /* Trans Mem state: Active */
#define __MASK(X)       (1UL<<(X))
#define MSR_TM          __MASK(MSR_TM_LG)       /* Transactional Mem Available */
#define MSR_TS_S        __MASK(MSR_TS_S_LG)     /*  Transaction Suspended */
#define MSR_TS_T        __MASK(MSR_TS_T_LG)     /*  Transaction Suspended */
#define COUNT_MAX       1000		/* Number of interactions */
#define THREADS		1

#define ARG_MESS_WITH_TM_AT	0x1
#define ARG_MESS_WITH_TM_BEFORE	0x2
#define ARG_MESS_WITH_MSR_AT	0x4
#define ARG_FOREVER		0x10
#define ARG_BOOM		ARG_MESS_WITH_TM_AT | ARG_MESS_WITH_TM_BEFORE | ARG_MESS_WITH_MSR_AT

static int args;
static int nthread = THREADS;
static int count_max = COUNT_MAX;

/* checkpoint context */
ucontext_t *ckuc;

/* Returns a 64-bits random number */
long long r(){
	long long f = rand();

	f = f<<32;
	f |= rand();

	return f;
}


/*
 * Set a pointer (ptr) value (nbytes wide) with random number, with
 * 1/chance probability
 */
int set_random(void *ptr, int chance, int nbytes)
{
	long long v;
	if ((rand() % chance) == 0) {
		switch (nbytes) {
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

/* Return true with 1/x probability */
int one_in_chance(int x)
{
	return rand()%x == 0;
}

/* Change TM states */
void mess_with_tm()
{
	/* Starts a transaction 33% of the time */
	if (one_in_chance(3)) {
		asm ("tbegin.	;"
		     "beq 8	;");
		/* And suspended half of them */
		if (one_in_chance(2))
			asm("tsuspend.	;");
	}

	/* Terminate 5% of them */
	if (one_in_chance(20))
		asm("tend.	;");
}

/* Signal handler that will be invoked with raise() */
void trap_signal_handler(int signo, siginfo_t *si, void *uc)
{
	ucontext_t *ucp = uc;

	ucp->uc_link = ckuc;

	/*
	 * Set uc_link in three possible ways:
	 *  - Setting a single 'int' in the whole chunk
	 *  - Cloning ucp into uc_link
	 *  - Allocating a new memory chunk
	 */
	if (one_in_chance(3))
		memset(ucp->uc_link, rand(), sizeof(ucontext_t));
	else if (one_in_chance(2))
		memcpy(ucp->uc_link, uc, sizeof(ucontext_t));
	else {
		free(ckuc);
		ckuc = malloc(sizeof(ucontext_t));
		ucp->uc_link = ckuc;
		madvise(ucp->uc_link, sizeof(ucontext_t), MADV_DONTNEED);
	}

	if (args & ARG_MESS_WITH_MSR_AT) {
		/* Changing the checkpointed registers */
		if (one_in_chance(4))
			ucp->uc_link->uc_mcontext.gp_regs[PT_MSR] |= MSR_TS_S;
		else
			if (one_in_chance(2))
				ucp->uc_link->uc_mcontext.gp_regs[PT_MSR] |=
							 MSR_TS_T;
			else
				ucp->uc_link->uc_mcontext.gp_regs[PT_MSR] |=
							MSR_TS_T | MSR_TS_S;

		/* Checking the current register context */
		if (one_in_chance(2))
			ucp->uc_mcontext.gp_regs[PT_MSR] |= MSR_TS_S;
		else
			if (one_in_chance(2))
				ucp->uc_mcontext.gp_regs[PT_MSR] |= MSR_TS_T;
			else
				ucp->uc_mcontext.gp_regs[PT_MSR] |=
						MSR_TS_T | MSR_TS_S;

	}


	/* 1/100 of the runs mess up with MSR */
	set_random(&ucp->uc_mcontext.gp_regs[PT_MSR], 10, 8);
	set_random(&ucp->uc_link->uc_mcontext.gp_regs[PT_MSR], 10, 8);

	set_random(&ucp->uc_mcontext.gp_regs[PT_NIP], 10, 8);
	set_random(&ucp->uc_link->uc_mcontext.gp_regs[PT_NIP], 10, 8);

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

	if (args & ARG_MESS_WITH_TM_BEFORE) {
		mess_with_tm();
	}
}

void seg_signal_handler(int signo, siginfo_t *si, void *uc)
{
	exit(0);
}


void *tm_trap_test(void *thrid)
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

	while (i < count_max) {
		pid_t t = fork();
		if (t == 0) {
			/* Once seed per process */
			srand(time(NULL) + getpid());
			if (args & ARG_MESS_WITH_TM_AT) {
				mess_with_tm();
			}
			raise(SIGUSR1);
			exit(0);
		} else {
			int ret;
			wait(&ret);
		}
		if (!(args & ARG_FOREVER))
			i++;
	}

	return NULL;
}


int tm_signal_force_msr(void)
{
	pthread_t *threads;

	threads = malloc(nthread*sizeof(pthread_t));
	int rc, t;

	for(t=0; t<nthread; t++){
		rc = pthread_create(&threads[t], NULL, tm_trap_test, (void *)&t);
	}

	for (t=0; t<nthread; t++) {
		rc = pthread_join(threads[t], NULL);
	}

	free(threads);

	return 0;
}

void show_help(char *name)
{
	printf("%s: Sigfuzzer for powerpc\n", name);
	printf("Usage:\n");
	printf("\t-b\tMess with TM before raising a SIGUSR1 signal\n");
	printf("\t-a\tMess with TM after raising a SIGUSR1 signal\n");
	printf("\t-m\tMess with MSR[TS] bits at signal handler machine context\n");
	printf("\t-x\tMess with everything above\n");
	printf("\t-f\tRun forever and does not exit\n");
	printf("\t-i\tAmount of interactions.	(Default = %d)\n", COUNT_MAX);
	printf("\t-t\tAmount of threads.	(Default = %d)\n", THREADS);
	exit(-1);
}

int main(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "bamxt:fi:h")) != -1) {
		if (opt == 'b') {
			printf("Mess with TM before signal\n");
			args |= ARG_MESS_WITH_TM_BEFORE;
		} else if (opt == 'a') {
			printf("Mess with TM at signal handler\n");
			args |= ARG_MESS_WITH_TM_AT;
		} else if (opt == 'm') {
			printf("Mess with MSR[TS] bits at signal handler machine context\n");
			args |= ARG_MESS_WITH_MSR_AT;
		} else if (opt == 'x') {
			printf("Running complete fuzzer\n");
			args |= ARG_BOOM;
		} else if (opt == 't') {
		        nthread = atoi(optarg);
			printf("Threads := %d\n", nthread);
		} else if (opt == 'f') {
			args |= ARG_FOREVER;
			printf("Press ^C to stop\n");
		} else if (opt == 'i') {
		        count_max = atoi(optarg);
			printf("Running for %d interactions\n", count_max);
		} else if (opt == 'h') {
			show_help(argv[0]);
		}

	}
	if (args)
		tm_signal_force_msr();
	else
		show_help(argv[0]);
}
