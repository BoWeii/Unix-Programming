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
    init = 1;
    return;
}

void set_realpath(const char *src, char *dst)
{
    // char path[BUFFER_MAX_SIZE] = {0};
    if (realpath(src, dst) == NULL)
    {
        strcpy(dst, "string untouched");
    }
    return;
}

void set_str32(const char *src, char *dst)
{
    int count = 0; // If a passed argument is a regular character buffer, print it out up to 32 bytes.
    while (*src && count < 32)
    {
        dst[count] = isprint(*src) ? *src : '.';
        src++;
        count++;
    }
}

void set_fd_path(int fd, char *actual_path)
{
    char *proc_fd = (char *)calloc(1024, sizeof(char));
    sprintf(proc_fd, "/proc/self/fd/%d", fd);
    if (readlink(proc_fd, actual_path, 1024) == -1)
    {
        strcpy(actual_path, "@@@@@@@@@@@@@@@@@@@@@@@@@@");
    }
    free(proc_fd);
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

    char dst[BUFFER_MAX_SIZE] = {0};
    set_realpath(pathname, dst);

    dprintf(target_fd, "[logger] chmod(\"%s\", \"%o\") = %d \n", dst, mode, ret);
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

    char dst[BUFFER_MAX_SIZE] = {0};
    set_realpath(pathname, dst);

    dprintf(target_fd, "[logger] chown(\"%s\", \"%d\", \"%d\") = %d \n", dst, owner, group, ret);
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

    char actual_path[BUFFER_MAX_SIZE] = {0};
    set_fd_path(fd, actual_path);

    dprintf(target_fd, "[logger] close(\"%s\") = %d \n", actual_path, 0);
    int ret = ori_close(fd);
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

    char dst[BUFFER_MAX_SIZE] = {0};
    set_realpath(path, dst);

    dprintf(target_fd, "[logger] creat(\"%s\", \"%o\") = %d \n", dst, mode, ret);
    return ret;
}

static int (*ori_fclose)(FILE *) = NULL;
int fclose(FILE *stream)
{
    redirect_logger();
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    ori_fclose = dlsym(handle, "fclose");
    if (ori_fclose == NULL)
        fprintf(stderr, "fail to call fclose \n");

    char actual_path[BUFFER_MAX_SIZE] = {0};
    set_fd_path(stream->_fileno, actual_path);

    dprintf(target_fd, "[logger] fclose(\"%s\") = %d \n", actual_path, 0);
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

    char actual_path[BUFFER_MAX_SIZE] = {0};
    set_realpath(pathname, actual_path);
    char str[BUFFER_MAX_SIZE] = {0};
    set_str32(mode, str);

    dprintf(target_fd, "[logger] fopen(\"%s\", \"%s\") = %p \n", actual_path, str, ret);
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

    char str[BUFFER_MAX_SIZE] = {0};
    set_str32(ptr, str);
    char actual_path[BUFFER_MAX_SIZE] = {0};
    set_fd_path(stream->_fileno, actual_path);

    dprintf(target_fd, "[logger] fread(\"%s\", \"%ld\", \"%ld\", \"%s\") = %ld \n", str, size, nmemb, actual_path, ret);
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

    char str[BUFFER_MAX_SIZE] = {0};
    set_str32(ptr, str);
    char actual_path[BUFFER_MAX_SIZE] = {0};
    set_fd_path(stream->_fileno, actual_path);

    dprintf(target_fd, "[logger] fwrite(\"%s\", \"%ld\", \"%ld\", \"%s\") = %ld \n", str, size, nmemb, actual_path, ret);
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

    char actual_path[BUFFER_MAX_SIZE] = {0};
    set_realpath(pathname, actual_path);

    dprintf(target_fd, "[logger] open(\"%s\", \"%o\", \"%o\") = %d \n", actual_path, flags, mode, ret);
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

    char actual_path[BUFFER_MAX_SIZE] = {0};
    set_fd_path(fd, actual_path);
    char str[BUFFER_MAX_SIZE] = {0};
    set_str32(buf, str);

    dprintf(target_fd, "[logger] read(\"%s\", \"%s\", \"%ld\") = %d \n", actual_path, str, count, ret);
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

    char actual_path[BUFFER_MAX_SIZE] = {0};
    set_realpath(path, actual_path);
    
    dprintf(target_fd, "[logger] remove(\"%s\") = %d \n", actual_path, 0);
    int ret = ori_remove(path);
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

    dprintf(target_fd, "[logger] rename(\"%s\", \"%s\") = %d \n", oldpath, newpath, ret);
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

    dprintf(target_fd, "[logger] tmpfile() = %p \n", ret);
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

    char actual_path[BUFFER_MAX_SIZE] = {0};
    set_fd_path(fd, actual_path);
    char str[BUFFER_MAX_SIZE] = {0};
    set_str32(buf, str);

    dprintf(target_fd, "[logger] write(\"%s\", \"%s\", \"%ld\") = %d \n", actual_path, str, count, ret);
    return ret;
}