#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <assert.h>

#include <sys/wait.h>
#include <sys/types.h>

#include "proc-common.h"
#include "request.h"

/* Compile-time parameters. */
#define SCHED_TQ_SEC 2                /* time quantum */
#define TASK_NAME_SZ 60               /* maximum size for a task's name */
#define SHELL_EXECUTABLE_NAME "shell" /* executable for shell */

struct doublist_t{
	int id;
	int priority;
	pid_t pid;
	char *name;
	struct doublist_t *next;
	struct doublist_t *prev;
} *doublist;

int count,flag = 0,priorityflag = 0;

/* Print a list of all tasks currently being scheduled.  */
static void
sched_print_tasks(void)
{
	//assert(0 && "Please fill me!");
	int f = doublist -> id;
	struct doublist_t *y;
	printf("%d %d %s %d\n",doublist -> id,doublist -> pid,doublist -> name,doublist -> priority);
	y = doublist -> next;	//xreiazetai to y?
	while(y -> id != f){
		printf("%d %d %s %d\n",y -> id,y -> pid,y -> name,y -> priority);
		y = y -> next;
	}
}
//handle priority issues
static int
higherP(int iden)
{
	struct doublist_t *new;
	new = doublist;
	while(new -> id != iden){
		new = new -> next;
	}
	if(new -> id == iden){
		priorityflag = 1;
		new -> priority = 1;
	}
	return -ENOSYS;
}

static int
lowerP(int iden)
{
	struct doublist_t *new;
	int i;
	new = doublist;
	//an de briskomaste sto shell pou theloume na xronodromologoume stathera
	if (iden != 1){
		while(new -> id != iden){
			new = new -> next;
		}
		if(new -> id == iden){
			new -> priority = 0;
		}
		priorityflag = 0;
		for(i=1;i <= count;i++){
			if ((new -> priority == 1)&&(new -> id != 1)) priorityflag=1;
			new = new -> next;
		}
	}
	else printf("Can't decrease Shell's priority\n");
	return -ENOSYS;
}

/* Send SIGKILL to a task determined by the value of its
 * scheduler-specific id.
 */
static int
sched_kill_task_by_id(int iden)
{
	//assert(0 && "Please fill me!");
	int cntr = count;
	struct doublist_t *temp1,*temp2;
	temp1 = doublist;
	while (( (temp1 -> id) != iden) && (cntr > 0)){ //na to kanoume opws panw(?)
		temp1 = temp1 -> next;
		cntr--;
	}
	if(temp1 -> id == iden){
		//thetw to flag 1 kai diagrafw ti diergasia apo ti lista edw
		flag = 1;
		temp2 = temp1;
		count--;
		kill(temp1 -> pid,SIGKILL);
		temp1 -> prev -> next = temp2 -> next;
		temp1 -> next -> prev = temp2 -> prev;
		temp2 = temp2 -> next;
		free(temp1);
	}
	return -ENOSYS;
}


/* Create a new task.  */
static void
sched_create_task(char *executable)
{
	//assert(0 && "Please fill me!");
	//char *name = executable;
	pid_t p;
	struct doublist_t *new,*temp;
	new = (struct doublist_t *)malloc(sizeof(struct doublist_t));
	temp = doublist -> next;
	new -> next = temp;
	new -> prev = doublist;
	doublist -> next = new;
	temp -> prev = new;
	p = fork();
	if (p<0){
		perror("fork");
		exit(1);
	}
	if (p==0){ 						//child
		char *arg[] = {executable,NULL,NULL,NULL};
		char *env[] = {NULL};
		raise(SIGSTOP);
		execve(executable,arg,env);
		perror("execve");
		exit(1);
	}
	//father
	count++;
	new -> pid = p;
	new -> id = count;
	new -> name = strdup(executable);
}

/* Process requests by the shell.  */
static int
process_request(struct request_struct *rq)
{
	switch (rq->request_no) {
		case REQ_PRINT_TASKS:
			sched_print_tasks();
			return 0;

		case REQ_KILL_TASK:
			return sched_kill_task_by_id(rq->task_arg);

		case REQ_EXEC_TASK:
			sched_create_task(rq->exec_task_arg);
			return 0;

		case REQ_HIGH_TASK:
			higherP(rq->task_arg);
			return 0;

		case REQ_LOW_TASK:
			lowerP(rq->task_arg);
			return 0;

		default:
			return -ENOSYS;
	}
}

/* 
 * SIGALRM handler
 */
static void
sigalrm_handler(int signum)
{
	//assert(0 && "Please fill me!");
	kill(doublist -> pid, SIGSTOP);
}

/* 
 * SIGCHLD handler
 */
static void
sigchld_handler(int signum)
{
	//assert(0 && "Please fill me!");
	int status, i;
	struct doublist_t *new;
	pid_t p;
	for (;;){
		p = waitpid(-1, &status, WUNTRACED | WNOHANG);
		if (p < 0){
			perror("waitpid");
			exit(1);
		}
		if (p == 0) break;
		explain_wait_status(p,status);
		//an prepei na diagrafei
		if(WIFEXITED(status) || (WIFSIGNALED(status))){
			//to flag einai 1 an exei diagrafei apo pio panw to stoixeio tis listas
			if (flag == 0){
				struct doublist_t *y = doublist -> next;
				doublist -> next -> prev = doublist -> prev;
				doublist -> prev -> next = doublist -> next;
				free(doublist);
				doublist = y;
				count--;
			}
			flag = 0;		
			alarm(SCHED_TQ_SEC);
			kill(doublist -> pid,SIGCONT); //shma gia na arxisei h epomenh diergasia
			new = doublist;
			priorityflag=0;
			//ksanaelegxoume an iparxei diergasia me priority HIGH ( = 1 )
			for (i = 1; i <= count; i++){
				if (( new -> priority == 1) && ( new -> id != 1 )) priorityflag = 1;
				new = new -> next;
			}
		}
		if(WIFSTOPPED(status)){
			if (priorityflag == 0) {
				//an den iparxei HIGH, sinexizoume kanonika
				doublist = doublist -> next;
				alarm(SCHED_TQ_SEC);
				kill(doublist -> pid,SIGCONT);
			}
			else {
				//an iparxoun diergasies me HIGH, anazitisi epomenis HIGH
				doublist = doublist -> next;
				while(doublist -> priority == 0) doublist = doublist -> next;
				alarm(SCHED_TQ_SEC);
				kill(doublist -> pid,SIGCONT);
			}
		}
	}
}

/* Disable delivery of SIGALRM and SIGCHLD. */
static void
signals_disable(void)
{
	sigset_t sigset;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigaddset(&sigset, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sigset, NULL) < 0) {
		perror("signals_disable: sigprocmask");
		exit(1);
	}
}

/* Enable delivery of SIGALRM and SIGCHLD.  */
static void
signals_enable(void)
{
	sigset_t sigset;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigaddset(&sigset, SIGCHLD);
	if (sigprocmask(SIG_UNBLOCK, &sigset, NULL) < 0) {
		perror("signals_enable: sigprocmask");
		exit(1);
	}
}


/* Install two signal handlers.
 * One for SIGCHLD, one for SIGALRM.
 * Make sure both signals are masked when one of them is running.
 */
static void
install_signal_handlers(void)
{
	sigset_t sigset;
	struct sigaction sa;

	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGCHLD);
	sigaddset(&sigset, SIGALRM);
	sa.sa_mask = sigset;
	if (sigaction(SIGCHLD, &sa, NULL) < 0) {
		perror("sigaction: sigchld");
		exit(1);
	}

	sa.sa_handler = sigalrm_handler;
	if (sigaction(SIGALRM, &sa, NULL) < 0) {
		perror("sigaction: sigalrm");
		exit(1);
	}

	/*
	 * Ignore SIGPIPE, so that write()s to pipes
	 * with no reader do not result in us being killed,
	 * and write() returns EPIPE instead.
	 */
	if (signal(SIGPIPE, SIG_IGN) < 0) {
		perror("signal: sigpipe");
		exit(1);
	}
}

static void
do_shell(char *executable, int wfd, int rfd)
{
	char arg1[10], arg2[10];
	char *newargv[] = { executable, NULL, NULL, NULL };
	char *newenviron[] = { NULL };

	sprintf(arg1, "%05d", wfd);
	sprintf(arg2, "%05d", rfd);
	newargv[1] = arg1;
	newargv[2] = arg2;

	raise(SIGSTOP);
	execve(executable, newargv, newenviron);

	/* execve() only returns on error */
	perror("scheduler: child: execve");
	exit(1);
}

/* Create a new shell task.
 *
 * The shell gets special treatment:
 * two pipes are created for communication and passed
 * as command-line arguments to the executable.
 */
static void
sched_create_shell(char *executable, int *request_fd, int *return_fd)
{
	pid_t p;
	int pfds_rq[2], pfds_ret[2];

	if (pipe(pfds_rq) < 0 || pipe(pfds_ret) < 0) {
		perror("pipe");
		exit(1);
	}

	p = fork();

	if (p < 0) {
		perror("scheduler: fork");
		exit(1);
	}

	if (p == 0) {
		/* Child */
		close(pfds_rq[0]);
		close(pfds_ret[1]);
		do_shell(executable, pfds_rq[1], pfds_ret[0]);
		assert(0);
	}
	/* Parent */
	//pername to pid tou shell sti global lista
	doublist -> pid = p;
	close(pfds_rq[1]);
	close(pfds_ret[0]);
	*request_fd = pfds_rq[0];
	*return_fd = pfds_ret[1];
}

static void
shell_request_loop(int request_fd, int return_fd)
{
	int ret;
	struct request_struct rq;

	/*
	 * Keep receiving requests from the shell.
	 */
	for (;;) {
		if (read(request_fd, &rq, sizeof(rq)) != sizeof(rq)) {
			perror("scheduler: read from shell");
			fprintf(stderr, "Scheduler: giving up on shell request processing.\n");
			break;
		}

		signals_disable();
		ret = process_request(&rq);
		signals_enable();

		if (write(return_fd, &ret, sizeof(ret)) != sizeof(ret)) {
			perror("scheduler: write to shell");
			fprintf(stderr, "Scheduler: giving up on shell request processing.\n");
			break;
		}
	}
}

int main(int argc, char *argv[])
{
	int nproc;
	int i;
	pid_t p;
	/* Two file descriptors for communication with the shell */
	static int request_fd, return_fd;
	struct doublist_t *head;
	doublist = (struct doublist_t *)malloc(sizeof(struct doublist_t));

	/* Create the shell. */
	sched_create_shell(SHELL_EXECUTABLE_NAME, &request_fd, &return_fd);
	/* TODO : add the shell to the scheduler's tasks */
	
	doublist -> id = 1;
	doublist -> name = "shell";
	doublist -> priority = 1;
	head = (struct doublist_t *)malloc(sizeof(struct doublist_t));
	doublist -> next = head;
	head -> prev = doublist;
	for(i = 1; i < argc; i++){
		p = fork();
		if (p<0){
			perror("fork");
			exit(1);
		}
		if(p == 0){
			char *arg[] = {argv[i],NULL,NULL,NULL};
			char *env[] = {NULL};
			raise(SIGSTOP);
			execve(argv[i],arg,env);
			perror("execve");
			exit(1);
		}
		head -> id = i + 1;
		head -> pid = p;
		head -> name = argv[i];
		head -> priority = 0;
		if(i != argc - 1){
			head -> next = (struct doublist_t *)malloc(sizeof(struct doublist_t));
			head -> next -> prev = head;
			head = head -> next;
		}
	}
	head -> next = doublist;
	doublist -> prev = head;

	/*
	 * For each of argv[1] to argv[argc - 1],
	 * create a new child process, add it to the process list.
	 */

	nproc = argc; /* number of proccesses goes here */
	count = argc;
	/* Wait for all children to raise SIGSTOP before exec()ing. */
	wait_for_ready_children(nproc);

	/* Install SIGALRM and SIGCHLD handlers. */
	install_signal_handlers();

	if (nproc == 0) {
		fprintf(stderr, "Scheduler: No tasks. Exiting...\n");
		exit(1);
	}
	
	alarm(SCHED_TQ_SEC);
	kill(doublist -> pid,SIGCONT);

	shell_request_loop(request_fd, return_fd);

	/* Now that the shell is gone, just loop forever
	 * until we exit from inside a signal handler.
	 */
	while (pause())
		;

	/* Unreachable */
	fprintf(stderr, "Internal error: Reached unreachable point\n");
	return 1;
}
