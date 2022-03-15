#include <iostream>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <algorithm>

using namespace std;

#define NO_NODE "NO_NODE"
#define BUF_MAX 1024
#define CMD_DISPLAY_MAX (90 + 1)
#define USER_DISPLAY_MAX (100 + 1)

typedef struct pid_info_t
{
    string cmd;
    pid_t pid;
    string user;
    string fd;
    string _type;
    string inode;
    char path[PATH_MAX];

} pid_info_t;

void print_header()
{
    printf("%-9s %5s %10s %4s %9s %10s %s\n",
           "COMMAND",
           "PID",
           "USER",
           "FD",
           "TYPE",
           "NODE",
           "NAME");
}

void get_username_byPid(pid_info_t &info, uid_t uid)
{
    struct passwd *pws;
    pws = getpwuid(uid);
    if (pws)
    {
        info.user = pws->pw_name;
    }
    else
    {
        info.user = "???";
    }
}
void get_command_byPid(pid_info_t &info, const int pid)
{
    char *name = (char *)calloc(1024, sizeof(char));
    if (name)
    {
        sprintf(name, "/proc/%d/comm", pid);
        FILE *f = fopen(name, "r");
        if (f)
        {
            size_t size;
            size = fread(name, sizeof(char), 1024, f);
            if (size > 0)
            {
                if ('\n' == name[size - 1])
                    name[size - 1] = '\0';
            }
            fclose(f);
        }
    }
    string tmp(name);
    free(name);
    info.cmd = tmp;
}

void get_file_type(pid_info_t &info, const char *file_path)
{
    struct stat _stat;
    stat(file_path, &_stat);
    switch (_stat.st_mode & S_IFMT)
    {
    case S_IFBLK:
        info._type = "BLK"; // block device
        break;
    case S_IFCHR:
        info._type = "CHR"; // character device
        break;
    case S_IFDIR:
        info._type = "DIR"; // directory
        break;
    case S_IFIFO:
        info._type = "FIFO"; // fifo/pipe
        break;
    case S_IFLNK:
        info._type = "SYM"; // symbolink
        break;
    case S_IFREG:
        info._type = "REG"; // regular file
        break;
    case S_IFSOCK:
        info._type = "SOCK"; // socket
        break;
    default:
        info._type = "unknown";
        break;
    }
}

void print_byFd(pid_info_t info, string fd)
{
    string name_path(info.path);
    struct stat _stat;
    if (fd == "cwd")
    {
        name_path += "cwd";
    }
    else if (fd == "rtd")
    {
        name_path += "root";
    }
    else if (fd == "txt")
    {
        name_path += "exe";
    }
    const char *symbolic_path = name_path.c_str();
    char *actual_path = (char *)calloc(1024, sizeof(char));
    if (readlink(symbolic_path, actual_path, 1024) != -1) // has permission
    {
        name_path = "";
        char *copy = actual_path;
        while (*copy)
        {
            name_path += *copy;
            copy++;
        }
        stat(actual_path, &_stat);
        info.inode = to_string(_stat.st_ino);
    }
    else // no permission
    {
        name_path += " (readlink: Permission denied)";
        info.inode = "";
    }
    get_file_type(info, actual_path);

    printf("%-9s %5d %10s %4s %9s %10s %s\n",
           (info.cmd).c_str(),
           info.pid,
           (info.user).c_str(),
           fd.c_str(),
           (info._type).c_str(),
           (info.inode).c_str(),
           name_path.c_str());
    free(actual_path);
}

void get_name_fromMaps(string line, string &name, pid_info_t &info, bool &over_head)
{
    stringstream ss(line);
    string tmp[7];
    int index = 0;
    while (ss >> tmp[index++])
    {
    }
    if (stoi(tmp[4]) > 0)
    {
        info.inode = tmp[4];
        name = tmp[5];
    }
    if (!over_head && tmp[5] == "[heap]")
    {
        over_head = true;
        name = NO_NODE;
    }
    info.fd = tmp[6] == "(deleted)" ? "DEL" : "mem";
}

void print_mem(pid_info_t info)
{
    string name_path(info.path);
    name_path += "maps";
    const char *actual_path = name_path.c_str();
    ifstream maps(name_path);
    if (!maps.is_open())
    {
        cerr << "permission deniled\n";
        return;
    }
    string line;
    vector<string> names;
    string name = "";
    bool over_head = false;

    while (getline(maps, line))
    {
        get_name_fromMaps(line, name, info, over_head);
        if (over_head && name != NO_NODE && find(names.begin(), names.end(), name) == names.end())
        {
            names.push_back(name);
            printf("%-9s %5d %10s %4s %9s %10s %s\n",
                   (info.cmd).c_str(),
                   info.pid,
                   (info.user).c_str(),
                   info.fd.c_str(),
                   "REG",
                   info.inode.c_str(),
                   name.c_str());
        }
    }
}

void print_pidcontent(pid_t pid)
{
    pid_info_t info;
    struct stat _stat;
    snprintf(info.path, sizeof(info.path), "/proc/%d/", pid); // set info.path
    if (!stat(info.path, &_stat))
    {
        info.pid = pid;
        get_username_byPid(info, _stat.st_uid);
        get_command_byPid(info, pid);
        print_byFd(info, "cwd"); // FD=cwd
        print_byFd(info, "rtd"); // FD=rtd
        print_byFd(info, "txt"); // FD=txt
        print_mem(info);
        // print_mode();
        // print_fd();
    }
}

int main()
{
    long int pid = 0;
    char *endptr;
    DIR *dir = opendir("/proc");
    if (dir == NULL)
    {
        cout << "Couldn't open /proc\n";
        return -1;
    }
    struct dirent *de;
    print_header();
    while ((de = readdir(dir)))
    {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        // Only inspect directories that are PID numbers
        pid = strtol(de->d_name, &endptr, 10);
        if (*endptr != '\0')
            continue;
        if (pid == 1373)
        {
            print_pidcontent(pid);
        }
    }

    return 0;
}