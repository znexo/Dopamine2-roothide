#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <dlfcn.h>
#include <os/log.h>
#include "syscall.h"
#include "litehook.h"
#include <libjailbreak/jbclient_xpc.h>

extern void _malloc_fork_prepare(void);
extern void _malloc_fork_parent(void);
extern void xpc_atfork_prepare(void);
extern void xpc_atfork_parent(void);
extern void dispatch_atfork_prepare(void);
extern void dispatch_atfork_parent(void);
extern void __fork(void);

int childToParentPipe[2];
int parentToChildPipe[2];
static void openPipes(void)
{
	if (pipe(parentToChildPipe) < 0 || pipe(childToParentPipe) < 0) {
		abort();
	}
}
static void closePipes(void)
{
	if (ffsys_close(parentToChildPipe[0]) != 0 || ffsys_close(parentToChildPipe[1]) != 0 || ffsys_close(childToParentPipe[0]) != 0 || ffsys_close(childToParentPipe[1]) != 0) {
		abort();
	}
}

void child_fixup(void)
{
	// Tell parent we are waiting for fixup now
	char msg = ' ';
	ffsys_write(childToParentPipe[1], &msg, sizeof(msg));

	// Wait until parent completes fixup
	ffsys_read(parentToChildPipe[0], &msg, sizeof(msg));
}

void parent_fixup(pid_t childPid)
{
	// Reenable some system functionality that XPC is dependent on and XPC itself
	// (Normally unavailable during __fork)
	_malloc_fork_parent();
	dispatch_atfork_parent();
	xpc_atfork_parent();

	// Wait until the child is ready and waiting
	char msg = ' ';
	read(childToParentPipe[0], &msg, sizeof(msg));

	// Child is waiting for wx_allowed + permission fixups now
	// Apply fixup
	int64_t fix_ret = jbclient_fork_fix(childPid);
	if (fix_ret != 0) {
		kill(childPid, SIGKILL);
		abort();
	}

	// Tell child we are done, this will make it resume
	write(parentToChildPipe[1], &msg, sizeof(msg));

	// Disable system functionality related to XPC again
	_malloc_fork_prepare();
	dispatch_atfork_prepare();
	xpc_atfork_prepare();
}

__attribute__((visibility ("default"))) pid_t forkfix___fork(void)
{
	openPipes();

	pid_t pid = ffsys_fork();
	if (pid < 0) {
		closePipes();
		return pid;
	}

	if (pid == 0) {
		child_fixup();
	}
	else {
		parent_fixup(pid);
	}

	closePipes();
	return pid;
}

#include <spawn.h>
struct _posix_spawn_args_desc {
	size_t		attr_size;	/* size of attributes block */
	posix_spawnattr_t	attrp;		/* pointer to block */
	size_t	file_actions_size;	/* size of file actions block */
	posix_spawn_file_actions_t file_actions;	/* pointer to block */
}; //https://opensource.apple.com/source/xnu/xnu-4570.31.3/bsd/sys/spawn_internal.h

#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
#define POSIX_SPAWN_SYSTEMHOOK_HANDLED	0x2000 // _POSIX_SPAWN_ALLOW_DATA_EXEC(0x2000) only used in DEBUG/DEVELOPMENT kernel
int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t *__restrict, int *__restrict) __API_AVAILABLE(macos(10.8), ios(6.0));

int (*posix_spawn_hook)(pid_t* pidp, const char* path, posix_spawn_file_actions_t* file_actions, posix_spawnattr_t * attrp,char *const argv,char *const envp);
int __posix_spawn(pid_t* pidp, const char * path, struct _posix_spawn_args_desc* ad, char *const argv, char *const envp);
int syscall__posix_spawn(pid_t* pidp, const char * path, struct _posix_spawn_args_desc* ad, char *const argv, char *const envp);
int new__posix_spawn(pid_t* pidp, const char * path, struct _posix_spawn_args_desc* ad, char *const argv, char *const envp)
{
	int ret;

    short flags = 0;
    int proctype = 0;

	if(ad && ad->attrp) {
		posix_spawnattr_getflags(&ad->attrp, &flags);
		posix_spawnattr_getprocesstype_np(&ad->attrp, &proctype);
	}

	if((proctype != POSIX_SPAWN_PROC_TYPE_DRIVER) && (flags & POSIX_SPAWN_SYSTEMHOOK_HANDLED)==0) {
		//reentrant
		ret = posix_spawn_hook(pidp, path, &ad->file_actions, &ad->attrp, argv, envp);

	} else {
		ret =  syscall__posix_spawn(pidp, path, ad, argv, envp);
	}

	return ret;
}

__attribute__((constructor)) static void initializer(void)
{
#ifdef __arm64e__
	litehook_hook_function((void *)&__fork, (void *)&forkfix___fork);
#endif

	posix_spawn_hook = dlsym(RTLD_DEFAULT, "posix_spawn_hook");
	litehook_hook_function((void *)&__posix_spawn, (void *)&new__posix_spawn);
}