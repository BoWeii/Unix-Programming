#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#define BUFFER_MAX_SIZE 128
// int __dup_stderr = dup(STDERR_FILENO);

#define STD_ERR_FD 2

void print_path_args(const char *arg, int last)
{
    char path[BUFFER_MAX_SIZE] = {0};
    if (realpath(arg, path) != NULL)
    {
        dprintf(STD_ERR_FD,"\"%s\"", path);
    }
    else
    {
        
        dprintf(STD_ERR_FD,"\"string untouched errno=%d\"",errno);
    }
    if (!last)
    {
        dprintf(STD_ERR_FD,", ");
    }
    return;
}
void print_fd_args(const char *arg, int last)
{
}
void print_oct_args(unsigned int arg, int last)
{
    dprintf(STD_ERR_FD,"%o", arg);
    if (!last)
    {
        dprintf(STD_ERR_FD,", ");
    }
}

void print_dec_args(unsigned int arg, int last)
{
    dprintf(STD_ERR_FD,"%d", arg);
    if (!last)
    {
        dprintf(STD_ERR_FD,", ");
    }
}

void print_str_args(const char *arg, int last)
{
    dprintf(STD_ERR_FD,"\"");
    while (*arg)
    {
        if (isprint(*arg))
        {
            dprintf(STD_ERR_FD,"%c", *arg);
        }
        else
        {
            dprintf(STD_ERR_FD,".");
        }
        arg++;
    }

    dprintf(STD_ERR_FD,"\"");
    if (!last)
    {
        dprintf(STD_ERR_FD,", ");
    }
}

void print_fd(int fd, int last)
{
    char *proc_fd = (char *)calloc(1024, sizeof(char));
    char *actual_path = (char *)calloc(1024, sizeof(char));
    sprintf(proc_fd, "/proc/self/fd/%d", fd);
    // pid_t pid = getpid();
    // char *proc_fd = (char *)calloc(1024, sizeof(char));
    // char *actual_path = (char *)calloc(1024, sizeof(char));
    // sprintf(proc_fd, "/proc/%d/fd/%d", pid,fd);
    if (readlink(proc_fd, actual_path, 1024) != -1)
    {
        dprintf(STD_ERR_FD,"\"%s\"", actual_path);
    }
    else
    {
        dprintf(STD_ERR_FD,"%s", "@@@@@@@@@@@@@@@@@@@@@@@@@@");
    }
    if (!last)
    {
        dprintf(STD_ERR_FD,", ");
    }
    free(proc_fd);
    free(actual_path);
    return;
}

/*
    function part
*/
static int (*ori_chmod)(const char *, mode_t) = NULL;
int chmod(const char *pathname, mode_t mode)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_chmod = dlsym(handle, "chmod");
    if (ori_chmod == NULL)
        fprintf(stderr, "fail to call chmod \n");
    int ret = ori_chmod(pathname, mode);
    dprintf(STD_ERR_FD,"[logger] %s", "chmod(");
    print_path_args(pathname, 0);
    print_oct_args(mode, 1);
    dprintf(STD_ERR_FD,") = %d\n", ret);
    return ret;
}

static int (*ori_chown)(const char *, uid_t, gid_t) = NULL;
int chown(const char *pathname, uid_t owner, gid_t group)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_chown = dlsym(handle, "chmod");
    if (ori_chown == NULL)
        fprintf(stderr, "fail to call chown \n");
    int ret = ori_chown(pathname, owner, group);
    dprintf(STD_ERR_FD,"[logger] %s", "chown(");
    print_path_args(pathname, 0);
    print_dec_args(owner, 0);
    print_dec_args(group, 1);
    dprintf(STD_ERR_FD,") = %d\n", ret);
    return ret;
}

static int (*ori_close)(int) = NULL;
int close(int fd)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_close = dlsym(handle, "close");
    if (ori_close == NULL)
        fprintf(stderr, "fail to call close \n");

    dprintf(STD_ERR_FD,"[logger] %s", "close(");
    print_fd(fd, 1);
    int ret = ori_close(fd);
    dprintf(STD_ERR_FD,") = %d\n", 0);
    return ret;
}
static int (*ori_creat)(const char *, mode_t) = NULL;
int creat(const char *path, mode_t mode)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_creat = dlsym(handle, "creat");
    if (ori_creat == NULL)
        fprintf(stderr, "fail to call creat \n");
    int ret = ori_creat(path, mode);

    dprintf(STD_ERR_FD,"[logger] %s", "creat(");
    print_path_args(path, 0);
    print_oct_args(mode, 1);
    dprintf(STD_ERR_FD,") = %d\n", ret);

    return ret;
}

static int (*ori_fclose)(FILE *) = NULL;
int fclose(FILE *stream)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_fclose = dlsym(handle, "fclose");
    if (ori_fclose == NULL)
        fprintf(stderr, "fail to call fopen \n");
    dprintf(STD_ERR_FD,"[logger] %s", "fclose(");
    print_fd(stream->_fileno, 1);
    dprintf(STD_ERR_FD,") = %d\n", 0);
    int ret = ori_fclose(stream);

    return ret;
}

static FILE *(*ori_fopen)(const char *, const char *) = NULL;
FILE *fopen(const char *pathname, const char *mode)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_fopen = dlsym(handle, "fopen");
    if (ori_fopen == NULL)
        fprintf(stderr, "fail to call fopen \n");
    FILE *ret = ori_fopen(pathname, mode);

    dprintf(STD_ERR_FD,"[logger] %s", "fopen(");
    print_path_args(pathname, 0);
    print_str_args(mode, 1);
    dprintf(STD_ERR_FD,") = %p\n", ret);

    return ret;
}

static size_t (*ori_fread)(void *restrict, size_t, size_t, FILE *restrict) = NULL;
size_t fread(void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_fread = dlsym(handle, "fread");
    if (ori_fread == NULL)
        fprintf(stderr, "fail to call fread \n");
    size_t ret = ori_fread(ptr, size, nmemb, stream);
    dprintf(STD_ERR_FD,"[logger] %s", "fread(");
    print_str_args(ptr, 0);
    print_dec_args(size, 0);
    print_dec_args(nmemb, 0);
    print_fd(stream->_fileno, 1);
    dprintf(STD_ERR_FD,") = %ld\n", ret);

    return ret;
}

static size_t (*ori_fwrite)(const void *restrict, size_t, size_t, FILE *restrict) = NULL;
size_t fwrite(const void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_fwrite = dlsym(handle, "fwrite");
    if (ori_fwrite == NULL)
        fprintf(stderr, "fail to call fwrite \n");
    size_t ret = ori_fwrite(ptr, size, nmemb, stream);
    dprintf(STD_ERR_FD,"[logger] %s", "fwrite(");
    print_str_args(ptr, 0);
    print_dec_args(size, 0);
    print_dec_args(nmemb, 0);
    print_fd(stream->_fileno, 1);
    dprintf(STD_ERR_FD,") = %ld\n", ret);

    return ret;
}

static int (*ori_open)(const char *, int, mode_t) = NULL;
int open(const char *pathname, int flags, mode_t mode)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_open = dlsym(handle, "open");
    if (ori_open == NULL)
        fprintf(stderr, "fail to call open \n");
    int ret = ori_open(pathname, flags, mode);
    dprintf(STD_ERR_FD,"[logger] %s", "open(");
    print_path_args(pathname, 0);
    print_oct_args(flags, 0);
    print_oct_args(mode, 1);
    dprintf(STD_ERR_FD,") = %d\n", ret);

    return ret;
}
static ssize_t (*ori_read)(int, void *, size_t) = NULL;
ssize_t read(int fd, void *buf, size_t count)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_read = dlsym(handle, "read");
    if (ori_read == NULL)
        fprintf(stderr, "fail to call read \n");
    int ret = ori_read(fd, buf, count);
    dprintf(STD_ERR_FD,"[logger] %s", "read(");
    print_fd(fd, 0);
    print_str_args(buf, 0);
    print_dec_args(count, 1);
    dprintf(STD_ERR_FD,") = %d\n", ret);
    return ret;
}
static int (*ori_remove)(const char *) = NULL;
int remove(const char *path)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_remove = dlsym(handle, "remove");
    if (ori_remove == NULL)
        fprintf(stderr, "fail to call remove \n");
    dprintf(STD_ERR_FD,"[logger] %s", "remove(");
    print_path_args(path, 1);
    int ret = ori_remove(path);
    dprintf(STD_ERR_FD,") = %d\n", ret);
    return ret;
}

static int (*ori_rename)(const char *, const char *) = NULL;
int rename(const char *oldpath, const char *newpath)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_rename = dlsym(handle, "rename");
    if (ori_rename == NULL)
        fprintf(stderr, "fail to call rename \n");
    int ret = ori_rename(oldpath, newpath);

    dprintf(STD_ERR_FD,"[logger] %s", "rename(");
    print_str_args(oldpath, 0);
    print_str_args(newpath, 1);
    dprintf(STD_ERR_FD,") = %d\n", ret);
    return ret;
}

static FILE *(*ori_tmpfile)(void) = NULL;
FILE *tmpfile(void)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_tmpfile = dlsym(handle, "tmpfile");
    if (ori_tmpfile == NULL)
        fprintf(stderr, "fail to call tmpfile \n");
    FILE *ret = ori_tmpfile();

    dprintf(STD_ERR_FD,"[logger] %s", "tmpfile(");
    dprintf(STD_ERR_FD,") = %p\n", ret);
    return ret;
}

static int (*ori_write)(int, const void *, size_t) = NULL;
ssize_t write(int fd, const void *buf, size_t count)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_write = dlsym(handle, "write");
    if (ori_write == NULL)
        fprintf(stderr, "fail to call write \n");
    int ret = ori_write(fd, buf, count);
    dprintf(STD_ERR_FD,"[logger] %s", "write(");
    print_fd(fd, 0);
    print_str_args(buf, 0);
    print_dec_args(count, 1);
    dprintf(STD_ERR_FD,") = %d\n", ret);
    return ret;
}