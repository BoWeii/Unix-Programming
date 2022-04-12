#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#define BUFFER_MAX_SIZE 128
// int __dup_stderr = dup(STDERR_FILENO);

#define STDERR_FD 2
#define O_WRONLY 01
#define O_CREAT 0100
int target_fd = 0;
int init = 0;

void redirect_logger()
{
    if (init)
    {
        return;
    }
    target_fd = atoi(getenv("OUTPUT_FD"));
    // printf("In init targer fd=%d\n",target_fd);
    init = 1;
    // dup2(target, STDERR_FILENO);
    // close(target);
    // setenv("LD_PRELOAD", so, 1);
    return;
}

void print_path_args(const char *arg, int last)
{
    char path[BUFFER_MAX_SIZE] = {0};
    if (realpath(arg, path) != NULL)
    {
        dprintf(target_fd, "\"%s\"", path);
    }
    else
    {

        dprintf(target_fd, "\"string untouched errno=%d\"", errno);
    }
    if (!last)
    {
        dprintf(target_fd, ", ");
    }
    return;
}
void print_fd_args(const char *arg, int last)
{
}
void print_oct_args(unsigned int arg, int last)
{
    dprintf(target_fd, "%o", arg);
    if (!last)
    {
        dprintf(target_fd, ", ");
    }
}

void print_dec_args(unsigned int arg, int last)
{
    dprintf(target_fd, "%d", arg);
    if (!last)
    {
        dprintf(target_fd, ", ");
    }
}

void print_str_args(const char *arg, int last)
{
    int count = 0; // If a passed argument is a regular character buffer, print it out up to 32 bytes.
    dprintf(target_fd, "\"");
    while (*arg && count < 32)
    {

        if (isprint(*arg))
        {
            dprintf(target_fd, "%c", *arg);
        }
        else
        {
            dprintf(target_fd, ".");
        }
        arg++;
        count++;
    }

    dprintf(target_fd, "\"");
    if (!last)
    {
        dprintf(target_fd, ", ");
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
        dprintf(target_fd, "\"%s\"", actual_path);
    }
    else
    {
        dprintf(target_fd, "%s", "@@@@@@@@@@@@@@@@@@@@@@@@@@");
    }
    if (!last)
    {
        dprintf(target_fd, ", ");
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
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_chmod = dlsym(handle, "chmod");
    if (ori_chmod == NULL)
        fprintf(stderr, "fail to call chmod \n");
    int ret = ori_chmod(pathname, mode);
    dprintf(target_fd, "[logger] %s", "chmod(");
    print_path_args(pathname, 0);
    print_oct_args(mode, 1);
    dprintf(target_fd, ") = %d\n", ret);
    return ret;
}

static int (*ori_chown)(const char *, uid_t, gid_t) = NULL;
int chown(const char *pathname, uid_t owner, gid_t group)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_chown = dlsym(handle, "chmod");
    if (ori_chown == NULL)
        fprintf(stderr, "fail to call chown \n");
    int ret = ori_chown(pathname, owner, group);
    dprintf(target_fd, "[logger] %s", "chown(");
    print_path_args(pathname, 0);
    print_dec_args(owner, 0);
    print_dec_args(group, 1);
    dprintf(target_fd, ") = %d\n", ret);
    return ret;
}

static int (*ori_close)(int) = NULL;
int close(int fd)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_close = dlsym(handle, "close");
    if (ori_close == NULL)
        fprintf(stderr, "fail to call close \n");

    dprintf(target_fd, "[logger] %s", "close(");
    print_fd(fd, 1);
    int ret = ori_close(fd);
    dprintf(target_fd, ") = %d\n", 0);
    return ret;
}
static int (*ori_creat)(const char *, mode_t) = NULL;
int creat(const char *path, mode_t mode)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_creat = dlsym(handle, "creat");
    if (ori_creat == NULL)
        fprintf(stderr, "fail to call creat \n");
    int ret = ori_creat(path, mode);

    dprintf(target_fd, "[logger] %s", "creat(");
    print_path_args(path, 0);
    print_oct_args(mode, 1);
    dprintf(target_fd, ") = %d\n", ret);

    return ret;
}

static int (*ori_fclose)(FILE *) = NULL;
int fclose(FILE *stream)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_fclose = dlsym(handle, "fclose");
    if (ori_fclose == NULL)
        fprintf(stderr, "fail to call fopen \n");
    dprintf(target_fd, "[logger] %s", "fclose(");
    print_fd(stream->_fileno, 1);
    dprintf(target_fd, ") = %d\n", 0);
    int ret = ori_fclose(stream);

    return ret;
}

static FILE *(*ori_fopen)(const char *, const char *) = NULL;
FILE *fopen(const char *pathname, const char *mode)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_fopen = dlsym(handle, "fopen");
    if (ori_fopen == NULL)
        fprintf(stderr, "fail to call fopen \n");
    FILE *ret = ori_fopen(pathname, mode);

    dprintf(target_fd, "[logger] %s", "fopen(");
    print_path_args(pathname, 0);
    print_str_args(mode, 1);
    dprintf(target_fd, ") = %p\n", ret);

    return ret;
}

static size_t (*ori_fread)(void *restrict, size_t, size_t, FILE *restrict) = NULL;
size_t fread(void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_fread = dlsym(handle, "fread");
    if (ori_fread == NULL)
        fprintf(stderr, "fail to call fread \n");
    size_t ret = ori_fread(ptr, size, nmemb, stream);
    dprintf(target_fd, "[logger] %s", "fread(");
    print_str_args(ptr, 0);
    print_dec_args(size, 0);
    print_dec_args(nmemb, 0);
    print_fd(stream->_fileno, 1);
    dprintf(target_fd, ") = %ld\n", ret);

    return ret;
}

static size_t (*ori_fwrite)(const void *restrict, size_t, size_t, FILE *restrict) = NULL;
size_t fwrite(const void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_fwrite = dlsym(handle, "fwrite");
    if (ori_fwrite == NULL)
        fprintf(stderr, "fail to call fwrite \n");
    size_t ret = ori_fwrite(ptr, size, nmemb, stream);
    dprintf(target_fd, "[logger] %s", "fwrite(");
    print_str_args(ptr, 0);
    print_dec_args(size, 0);
    print_dec_args(nmemb, 0);
    print_fd(stream->_fileno, 1);
    dprintf(target_fd, ") = %ld\n", ret);

    return ret;
}

static int (*ori_open)(const char *, int, mode_t) = NULL;
int open(const char *pathname, int flags, mode_t mode)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_open = dlsym(handle, "open");
    if (ori_open == NULL)
        fprintf(stderr, "fail to call open \n");
    int ret = ori_open(pathname, flags, mode);
    dprintf(target_fd, "[logger] %s", "open(");
    print_path_args(pathname, 0);
    print_oct_args(flags, 0);
    print_oct_args(mode, 1);
    dprintf(target_fd, ") = %d\n", ret);

    return ret;
}
static ssize_t (*ori_read)(int, void *, size_t) = NULL;
ssize_t read(int fd, void *buf, size_t count)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_read = dlsym(handle, "read");
    if (ori_read == NULL)
        fprintf(stderr, "fail to call read \n");
    int ret = ori_read(fd, buf, count);
    dprintf(target_fd, "[logger] %s", "read(");
    print_fd(fd, 0);
    print_str_args(buf, 0);
    print_dec_args(count, 1);
    dprintf(target_fd, ") = %d\n", ret);
    return ret;
}
static int (*ori_remove)(const char *) = NULL;
int remove(const char *path)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_remove = dlsym(handle, "remove");
    if (ori_remove == NULL)
        fprintf(stderr, "fail to call remove \n");
    dprintf(target_fd, "[logger] %s", "remove(");
    print_path_args(path, 1);
    int ret = ori_remove(path);
    dprintf(target_fd, ") = %d\n", ret);
    return ret;
}

static int (*ori_rename)(const char *, const char *) = NULL;
int rename(const char *oldpath, const char *newpath)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_rename = dlsym(handle, "rename");
    if (ori_rename == NULL)
        fprintf(stderr, "fail to call rename \n");
    int ret = ori_rename(oldpath, newpath);

    dprintf(target_fd, "[logger] %s", "rename(");
    print_str_args(oldpath, 0);
    print_str_args(newpath, 1);
    dprintf(target_fd, ") = %d\n", ret);
    return ret;
}

static FILE *(*ori_tmpfile)(void) = NULL;
FILE *tmpfile(void)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_tmpfile = dlsym(handle, "tmpfile");
    if (ori_tmpfile == NULL)
        fprintf(stderr, "fail to call tmpfile \n");
    FILE *ret = ori_tmpfile();

    dprintf(target_fd, "[logger] %s", "tmpfile(");
    dprintf(target_fd, ") = %p\n", ret);
    return ret;
}

static int (*ori_write)(int, const void *, size_t) = NULL;
ssize_t write(int fd, const void *buf, size_t count)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_write = dlsym(handle, "write");
    if (ori_write == NULL)
        fprintf(stderr, "fail to call write \n");
    int ret = ori_write(fd, buf, count);
    dprintf(target_fd, "[logger] %s", "write(");
    print_fd(fd, 0);
    print_str_args(buf, 0);
    print_dec_args(count, 1);
    dprintf(target_fd, ") = %d\n", ret);
    return ret;
}