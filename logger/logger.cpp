#include <iostream>
#include <string>
#include <filesystem>
#include <cstring>
#include <fcntl.h>
#include "unistd.h"

using namespace std;
#define BUFFER_MAX_SIZE 256
char current_path[BUFFER_MAX_SIZE];

void redirect_stderr(const char *fname)
{
    int newstderr = open(fname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    dup2(newstderr, STDERR_FILENO);
    close(newstderr);
    return;
}

int main(int argc, char *argv[])
{
    getcwd(current_path, BUFFER_MAX_SIZE);
    // cout << "pwd= " << current_path << endl;
    char USAGE[] = "usage: ./%s [-o file] [-p sopath] [--] cmd [cmd args ...] \n\
        -p: set the path to logger.so, default = ./logger.so \n\
        -o: print output to file, print to \"stderr\" if no file specified\n\
        --: separate the arguments for logger and for the command\n ";
    char logger[] = "logger";
    char logger_so_path[] = "./hw2.so";
    char output_to_file[] = "/dev/stderr";
    bool ready_to_recv_cmd = false;
    char cmd[99999];

    char cmd_ld_preload[] = "LD_PRELOAD=%s";
    char cmd_ld_preload_cancel[] = "LD_PRELOAD=";
    const char *cmd_cat = "%s %s";

    const char *opt_sring = "p:o:-:";
    int option;
    while ((option = getopt(argc, argv, opt_sring)) != -1)
    {
        switch (option)
        {
        case 'p':
            strcpy(logger_so_path, optarg);
            break;
        case 'o':
            strcpy(output_to_file, optarg);
            break;
        case '-':
            break;
        default:
            printf(USAGE, logger);
            return 0;
        }
    }

    redirect_stderr(output_to_file);
    if (argc > optind) // ready to execute the cmd
    {
        sprintf(cmd, cmd_ld_preload, logger_so_path);
        for (int i = optind; i < argc; i++)
        {
            sprintf(cmd, cmd_cat, cmd, argv[i]);
        }
        system(cmd);
        system(cmd_ld_preload_cancel);
    }
    else
    {
        printf("no command given.\n");
    }
    return 0;
}