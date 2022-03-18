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
#include <regex>
using namespace std;

#define NO_NODE "NO_NODE"
#define BUF_MAX 1024

vector<string> valid_type = {"REG", "CHR", "DIR", "FIFO", "SOCK", "unknown"};

string cmd_filter = "";
string file_filter = "";
string type_filter = "";
typedef struct result
{
    string cmd;
    pid_t pid;
    string user;
    string fd;
    string _type;
    string inode;
    string path;

} result;

vector<result> res;

void push_res(string cmd, pid_t pid, string user, string fd, string _type, string inode, string path)
{
    result tmp;
    tmp.cmd = cmd;
    tmp.pid = pid;
    tmp.user = user;
    tmp.fd = fd;
    tmp._type = _type;
    tmp.inode = inode;
    tmp.path = path;
    res.push_back(tmp);
}
void print_res()
{
    std::regex cmd_reg("(" + cmd_filter + ")"), file_reg("(" + file_filter + ")"), type_reg("(" + type_filter + ")");
    std::smatch file_match, type_match, cmd_match;
    std::ssub_match sm;
    for (auto &i : res)
    {
        if (regex_search(i.cmd, cmd_match, cmd_reg) && regex_search(i._type, type_match, type_reg) && regex_search(i.path, file_match, file_reg))
        {
            printf("%-9s %5d %10s %4s %9s %10s %s\n",
                   (i.cmd).c_str(),
                   i.pid,
                   (i.user).c_str(),
                   (i.fd).c_str(),
                   (i._type).c_str(),
                   (i.inode).c_str(),
                   (i.path).c_str());
        }
    }
}

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

size_t get_inodeIndex(string str)
{
    size_t index = 0;
    while (str[index++] != '[')
    {
    }
    return index;
}

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

void get_file_permission(pid_info_t &info, const char *file_path)
{
    struct stat _stat;
    lstat(file_path, &_stat); // print the permission without following symbolic link
    S_ISREG(_stat.st_mode);
    if ((_stat.st_mode & S_IRUSR) && (_stat.st_mode & S_IWUSR))
    {
        info.fd += "u";
    }
    else if (_stat.st_mode & S_IRUSR)
    {
        info.fd += "r";
    }
    else if (_stat.st_mode & S_IWUSR)
    {
        info.fd += "w";
    }
    else
    {
        info.fd += "-";
    }
}

void get_file_type(pid_info_t &info, const char *file_path)
{
    struct stat _stat;
    stat(file_path, &_stat);
    switch (_stat.st_mode & S_IFMT)
    {
    case S_IFCHR:
        info._type = "CHR"; // character device
        break;
    case S_IFDIR:
        info._type = "DIR"; // directory
        break;
    case S_IFIFO:
        info._type = "FIFO"; // fifo/pipe
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

bool is_skip_deleted(char *actual_path, pid_info_t &info)
{
    // if symbolic link file is deleted, return false
    struct stat _stat;
    string type(actual_path);
    string del = "(deleted)";
    std::string::size_type i = type.find(del);
    if (i != std::string::npos)
    {
        type.erase(i, del.length());
        strcpy(actual_path, type.c_str());
    }
    if (!stat(actual_path, &_stat))
    {
        info.inode = to_string(_stat.st_ino);
        get_file_type(info, actual_path);
        return false;
    }
    else
    {
        return true;
    }
}

void print_by_fd(pid_info_t info, string fd)
{
    string name_path(info.path);
    struct stat _stat;
    info.fd = fd;
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
    else if (fd == "NOFD")
    {
    }
    else
    {
        name_path += fd;
        get_file_permission(info, name_path.c_str());
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
        if (actual_path[0] == '/')
        {
            if (is_skip_deleted(actual_path, info))
            {
                return;
            }
            stat(actual_path, &_stat);
            info.inode = to_string(_stat.st_ino);
            get_file_type(info, actual_path);
        }
        else
        {
            string type(actual_path);
            if (type.find("socket:[") != std::string::npos)
            {
                size_t i = get_inodeIndex(type);
                while (type[i] != ']')
                {
                    info.inode += type[i++];
                }
                info._type = "SOCK";
            }
            else if (type.find("pipe:[") != std::string::npos)
            {
                size_t i = get_inodeIndex(type);
                ;
                while (type[i] != ']')
                {
                    info.inode += type[i++];
                }
                info._type = "FIFO";
            }
            else
            {
                info.inode="";
                info._type="unknown";
            }
        }
    }
    else // no permission
    {
        name_path += " (Permission denied)";
        info.inode = "";
        info._type = fd == "NOFD" ? "" : "unknown";
    }
    push_res(info.cmd,
             info.pid,
             info.user,
             info.fd,
             info._type,
             info.inode,
             name_path);
    free(actual_path);
}

void get_name_fromMaps(string line, string &name, pid_info_t &info)
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
    else
    {
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
        cout << name_path << " could not opened\n";
        return;
    }
    string line;
    vector<string> names;
    string name = "";
    // bool after_head = false;

    while (getline(maps, line))
    {
        get_name_fromMaps(line, name, info);
        if (name != NO_NODE && find(names.begin(), names.end(), name) == names.end())
        {
            names.push_back(name);
            push_res(info.cmd,
                     info.pid,
                     info.user,
                     info.fd,
                     "REG",
                     info.inode,
                     name);
        }
    }
}

void print_fd(pid_info_t info)
{
    const char *fd_path = "fd/";
    strncat(info.path, fd_path, sizeof(info.path));
    struct stat _stat;
    DIR *dir = opendir(info.path);
    if (dir == NULL)
    {
        print_by_fd(info, "NOFD"); // no permission
        return;
    }
    struct dirent *de;
    while ((de = readdir(dir)))
    {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;

        print_by_fd(info, de->d_name);
    }
}

void print_pid_content(pid_t pid)
{
    pid_info_t info;
    struct stat _stat;
    snprintf(info.path, sizeof(info.path), "/proc/%d/", pid); // set info.path
    if (!stat(info.path, &_stat))
    {
        info.pid = pid;
        get_username_byPid(info, _stat.st_uid);
        get_command_byPid(info, pid);
        print_by_fd(info, "cwd"); // FD=cwd
        print_by_fd(info, "rtd"); // FD=rtd
        print_by_fd(info, "txt"); // FD=txt
        print_mem(info);          // FD=mem & DEL
        print_fd(info);           // FD=[0-9]+[rwu] & NOFD
    }
}

void access_proc()
{
    long int pid = 0;
    char *endptr;
    DIR *dir = opendir("/proc");
    if (dir == NULL)
    {
        cout << "Couldn't open /proc\n";
        return;
    }
    struct dirent *de;
    while ((de = readdir(dir)))
    {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        pid = strtol(de->d_name, &endptr, 10);
        if (*endptr != '\0')
            continue;
        // Only PID number can pass
        // if (pid == 2900)
        print_pid_content(pid);
    }
}
bool process_argv(int args, char *argv[])
{
    for (int i = 1; i < args; i++)
    {
        if (i % 2 == 1)
        {
            if (argv[i][1] == 'c')
            {
                cmd_filter = string(argv[i + 1]);
            }
            else if (argv[i][1] == 't')
            {
                type_filter = string(argv[i + 1]);
                if (find(valid_type.begin(), valid_type.end(), type_filter) == valid_type.end())
                {
                    cout << "Invalid TYPE option.\n";
                    return false;
                }
            }
            else if (argv[i][1] == 'f')
            {
                file_filter = string(argv[i + 1]);
            }
        }
    }
    return true;
}

void remove_redundant()
{ // remove the first item in mem
    for (auto i = res.begin(); i != res.end(); i++)
    {
        if (i->fd == "txt" && (i + 1)->fd == "mem" && i->path == (i + 1)->path)
        {
            res.erase(i + 1);
        }
    }
}

int main(int args, char *argv[])
{
    if (!process_argv(args, argv))
    {
        return -1;
    }
    print_header();
    access_proc();
    remove_redundant();
    print_res();

    return 0;
}