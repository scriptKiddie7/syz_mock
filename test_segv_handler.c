// test_segv_handler.c — standalone test for SIGSEGV handling on FreeBSD
// Compile on FreeBSD: cc -o test_segv test_segv_handler.c
// Run: ./test_segv
//
// Tests whether the segv handler correctly catches signals at various
// address ranges, matching the executor's segv_handler logic.

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

static jmp_buf segv_env;
static volatile int skip_segv = 0;

static void handler(int sig, siginfo_t *info, void *ctx)
{
	uintptr_t addr = (uintptr_t)info->si_addr;
	const uintptr_t prog_start = 1 << 20;   // 1MB
	const uintptr_t prog_end = 100 << 20;   // 100MB (same as executor)
	int skip = skip_segv != 0;
	int valid = addr < prog_start || addr > prog_end;

	// FreeBSD SIGBUS override (same as executor)
	if (sig == SIGBUS)
		valid = 1;

	fprintf(stderr, "  HANDLER: sig=%d(%s) addr=%p skip=%d valid=%d → %s\n",
		sig, sig == SIGSEGV ? "SIGSEGV" : "SIGBUS",
		(void *)addr, skip, valid,
		(skip && valid) ? "SKIP (longjmp)" : "FATAL (exit)");

	if (skip && valid) {
		_longjmp(segv_env, 1);
	}
	fprintf(stderr, "  FATAL: handler did NOT skip, exiting\n");
	_exit(sig);
}

// Returns 1 if the signal was caught, 0 if no signal occurred
static int test_access(const char *desc, uintptr_t addr)
{
	fprintf(stderr, "TEST: %s (addr=%p)\n", desc, (void *)addr);
	skip_segv = 1;
	if (_setjmp(segv_env) == 0) {
		*(volatile char *)addr = 0;
		skip_segv = 0;
		fprintf(stderr, "  RESULT: no signal (address was accessible)\n\n");
		return 0;
	} else {
		skip_segv = 0;
		fprintf(stderr, "  RESULT: signal caught and skipped OK\n\n");
		return 1;
	}
}

int main(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_NODEFER | SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);

	fprintf(stderr, "=== SIGSEGV Handler Test for FreeBSD ===\n");
	fprintf(stderr, "prog_start = 0x%lx (1MB)\n", (unsigned long)(1 << 20));
	fprintf(stderr, "prog_end   = 0x%lx (100MB)\n", (unsigned long)(100 << 20));
	fprintf(stderr, "DataOffset = 0x%lx (100MB)\n\n", (unsigned long)(100 << 20));

	// Test 1: NULL address — should be caught (addr < prog_start → valid=1)
	test_access("NULL pointer (addr < prog_start, should SKIP)", 0);

	// Test 2: Address at 512KB — should be caught (addr < prog_start → valid=1)
	test_access("512KB (addr < prog_start, should SKIP)", 512 << 10);

	// Test 3: Address at 50MB — IN the protected range, should NOT be caught
	// This test will EXIT if the handler correctly refuses to skip
	fprintf(stderr, "TEST: 50MB (prog_start <= addr <= prog_end, should be FATAL)\n");
	fprintf(stderr, "  (skipping this test — it would terminate the process)\n\n");

	// Test 4: Address at exactly 100MB (= DataOffset = prog_end)
	// addr > prog_end → 100MB > 100MB → FALSE → valid=0 → FATAL!
	fprintf(stderr, "TEST: exactly 100MB = prog_end = DataOffset\n");
	fprintf(stderr, "  addr > prog_end → 0x6400000 > 0x6400000 → FALSE → valid=0\n");
	fprintf(stderr, "  (skipping this test — it would terminate the process)\n\n");

	// Test 5: Address at 100MB + 4096 — should be caught (addr > prog_end → valid=1)
	test_access("100MB + 4096 (addr > prog_end, should SKIP)", (100 << 20) + 4096);

	// Test 6: Address at 200MB — should be caught (addr > prog_end → valid=1)
	test_access("200MB (addr > prog_end, should SKIP)", 200 << 20);

	// Test 7: mmap at DataOffset (100MB) then unmap — test the boundary
	void *data = mmap((void *)(uintptr_t)(100 << 20), 4096,
			  PROT_READ | PROT_WRITE,
			  MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (data != MAP_FAILED) {
		fprintf(stderr, "TEST: mmap'd 100MB, unmapping, then accessing...\n");
		munmap(data, 4096);
		// Now access the unmapped page at exactly 100MB
		// addr=100MB, valid = (100MB > 100MB) = FALSE → FATAL
		fprintf(stderr, "  addr=100MB after unmap: valid=(100MB > 100MB)=FALSE → FATAL\n");
		fprintf(stderr, "  (skipping — would terminate)\n\n");
	}

	fprintf(stderr, "=== Summary ===\n");
	fprintf(stderr, "The handler REFUSES to skip SIGSEGV for addresses in [1MB, 100MB].\n");
	fprintf(stderr, "FreeBSD DataOffset=100MB sits exactly at prog_end boundary.\n");
	fprintf(stderr, "Addresses AT 100MB fail: (100MB > 100MB) is FALSE.\n");
	fprintf(stderr, "Addresses ABOVE 100MB pass: (100MB+N > 100MB) is TRUE.\n\n");
	fprintf(stderr, "To diagnose the real issue, add diagnostic output to segv_handler\n");
	fprintf(stderr, "in executor common.h to see the actual faulting address.\n");

	return 0;
}
