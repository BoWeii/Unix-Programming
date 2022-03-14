#include <iostream>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>

using namespace std;

#define BUF_MAX 1024
#define CMD_DISPLAY_MAX (90 + 1)
#define USER_DISPLAY_MAX (100 + 1)

typedef struct pid_info_t {
    pid_t pid;
    string user;
    string cmd;
    char path[PATH_MAX];
    ssize_t parent_length;
} pid_info_t;

string get_username(uid_t uid)
{
    struct passwd *pws;
    pws = getpwuid(uid);
    if(pws){
        return pws->pw_name;
    }else{
        return "???";
    }
}
string get_process_name_by_pid(const int pid)
{
    char* name = (char*)calloc(1024,sizeof(char));
    if(name){
        sprintf(name, "/proc/%d/comm",pid);
        FILE* f = fopen(name,"r");
        if(f){
            size_t size;
            size = fread(name, sizeof(char), 1024, f);
            if(size>0){
                if('\n'==name[size-1])
                    name[size-1]='\0';
            }
            fclose(f);
        }
    }
    string tmp(name);
    free(name);
    return tmp;
}



void print_file(pid_info_t &info,string type){
    string name_path(info.path);

    if(type=="cwd"){
        name_path+="cwd";
    }
    else if(type=="rtd"){
        name_path+="root";
    }
    else if(type=="txt"){
        name_path+="exe";
    }
    const char *symbolic_path=name_path.c_str();
    char *actual_path= (char*)calloc(1024,sizeof(char));
    if(readlink(symbolic_path,actual_path,1024)!=-1){
        name_path="";
        while(*actual_path){
            name_path+=*actual_path;
            actual_path++;
        }
    }else{
        name_path+=" (readlink: Permission denied)";
    }

    printf("%-9s %5d %10s %4s %9s %10s %s\n",
            (info.cmd).c_str(),
            info.pid,
            (info.user).c_str(),
            type.c_str(),
            "TODO",
            "TODO",
            name_path.c_str());
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

void print_pidcontent(pid_t pid){
    pid_info_t info;
    struct stat _stat;
    info.pid=pid;
    snprintf(info.path, sizeof(info.path), "/proc/%d/", pid);
    // cout<<info.path<<endl;
    if(!stat(info.path,&_stat)){
        info.user= get_username(_stat.st_uid);
    }
    info.cmd=get_process_name_by_pid(pid);
    // cout<<info.cmd<<endl;
    print_file(info,"cwd");
    print_file(info,"rtd");

}


int main(){
    long int pid = 0;
    char* endptr;
    DIR *dir = opendir("/proc");
    if (dir == NULL) {
            cout<<"Couldn't open /proc\n";
            return -1;
        }
    struct dirent* de;
    print_header();
    while ((de = readdir(dir))) {
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                continue;
            // Only inspect directories that are PID numbers
            pid = strtol(de->d_name, &endptr, 10);
            if (*endptr != '\0')
                continue;
            if(pid==1){
                print_pidcontent(pid);
            }
        }

    return 0;
}