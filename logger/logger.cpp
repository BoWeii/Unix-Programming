#include <iostream>
#include <string>
#include <filesystem>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "unistd.h"

using namespace std;
#define BUFFER_MAX_SIZE 256
char current_path[BUFFER_MAX_SIZE];

// void redirect_stderr(const char *fname)
// {
//     int newstderr = open(fname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
//     dup2(newstderr, STDERR_FILENO);
//     close(newstderr);
//     return;
// }

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
    char output_fd[10] = {'\0'};
    bool ready_to_recv_cmd = false;

    char cmd[9999] = {'\0'};
    char cmd_ld_preload[] = "LD_PRELOAD=%s";
    char cmd_ld_preload_cancel[] = "LD_PRELOAD=";
    char cmd_send_fd[] = "OUTPUT_FD=%s";
    const char *cmd_cat = "%s %s";

    const char *opt_sring = "p:o:-:";
    int option;
    bool is_ready_recv_cmd = false;
    int cur_argc = 1;
    for (; cur_argc < argc; cur_argc++)
    {
        if (!is_ready_recv_cmd)
        {
            if (argv[cur_argc][0] == '-')
            {
                if (argv[cur_argc][1] == 'p')
                {
                    strcpy(logger_so_path, argv[++cur_argc]);
                    continue;
                }
                else if (argv[cur_argc][1] == 'o')
                {
                    strcpy(output_to_file, argv[++cur_argc]);
                    continue;
                }
                else if (argv[cur_argc][1] == '-')
                {
                    cur_argc++;
                    break;
                }
                else
                {
                    printf("%s/%s: invalid option -- '%c'\n", current_path, logger, argv[cur_argc][1]);
                    printf(USAGE, logger);
                    return 0;
                }
            }
            else
            {
                break;
            }
        }
    }

    int file = open(output_to_file, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (file == -1)
    {
        file = creat(output_to_file, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    }

    int _fd = strcmp(output_to_file, "/dev/stderr") == 0 ? 2 : file;
    strcpy(output_fd, to_string(_fd).c_str());

    if (argc > cur_argc) // ready to execute the cmd
    {
        sprintf(cmd, cmd_ld_preload, logger_so_path); // LD_PRELOAD=
        sprintf(cmd_send_fd, cmd_send_fd, output_fd);
        sprintf(cmd, cmd_cat, cmd, cmd_send_fd); // OUTPUT_FD=
        for (; cur_argc < argc; cur_argc++)
        {
            sprintf(cmd, cmd_cat, cmd, argv[cur_argc]);
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