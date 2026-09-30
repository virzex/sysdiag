#ifndef _FTRACE_H_
#define _FTRACE_H_

#include <linux/module.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include <asm/special_insns.h>
#include <asm/processor-flags.h>

struct ftrace_hook {
    const char   *name;
    void         *function;
    void         *original;
    unsigned long address;
    int           nr;
};

#define HOOK(_nr, _name, _hook, _orig)  \
{                        \
    .nr       = (_nr),   \
    .name     = (_name), \
    .function = (_hook), \
    .original = (_orig), \
}

static unsigned long *sys_call_table;

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    if (!sys_call_table) {
        sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
        if (!sys_call_table) {
            printk(KERN_ERR "sysdiag: sys_call_table not found\n");
            return -ENOENT;
        }
    }

    hook->address = (unsigned long)&sys_call_table[hook->nr];
    *((unsigned long *)hook->original) = sys_call_table[hook->nr];

    printk(KERN_INFO "sysdiag: hooking %s (nr %d)\n", hook->name, hook->nr);
    return 0;
}

static inline void table_write(int nr, unsigned long fn)
{
    unsigned long cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
    sys_call_table[nr] = fn;
    write_cr0(cr0);
}

static int fh_install_hook(struct ftrace_hook *hook)
{
    int err = fh_resolve_hook_address(hook);
    if (err)
        return err;

    table_write(hook->nr, (unsigned long)hook->function);
    return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook)
{
    table_write(hook->nr, (unsigned long)hook->original);
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0; i < count; i++) {
        err = fh_install_hook(&hooks[i]);
        if (err)
            goto error;
    }
    return 0;

error:
    while (i != 0)
        fh_remove_hook(&hooks[--i]);
    return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
        fh_remove_hook(&hooks[i]);
}

#endif