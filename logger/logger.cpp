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

int main(int argc, char *argv[], char *envp[])
{
    char USAGE[] = "usage: ./%s [-o file] [-p sopath] [--] cmd [cmd args ...] \n\
        -p: set the path to logger.so, default = ./logger.so \n\
        -o: print output to file, print to \"stderr\" if no file specified\n\
        --: separate the arguments for logger and for the command\n ";
    char logger[] = "logger";
    char logger_so_path[] = "./hw2.so";
    char output_to_file[] = "/dev/stderr";
    char output_fd[10] = {'\0'};

    const char *opt_sring = "p:o:-:";
    int option;
    bool is_ready_recv_cmd = false;

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

    if (argc > optind) // ready to execute the cmd
    {
        int file_fd = 0;
        if (strcmp(output_to_file, "/dev/stderr") == 0)
        {
            file_fd = dup(2);
        }
        else
        {
            file_fd = open(output_to_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        }

        strcpy(output_fd, to_string(file_fd).c_str());
        char *cmd_ld_preload = (char *)calloc(100, sizeof(char));
        sprintf(cmd_ld_preload, "LD_PRELOAD=%s", logger_so_path);

        char *cmd_send_fd = (char *)calloc(50, sizeof(char));
        sprintf(cmd_send_fd, "OUTPUT_FD=%s", output_fd);

        int envp_size = 0;
        char **envp_ptr = envp;
        while (*envp_ptr++)
        {
            envp_size++;
        }
        char *envp2[envp_size + 2];
        memcpy(envp2, envp, (envp_size) * sizeof(char *));
        envp2[envp_size++] = cmd_ld_preload;
        envp2[envp_size++] = cmd_send_fd;
        envp2[envp_size] = NULL;

        execvpe(argv[optind], argv + optind, envp2);

        free(cmd_ld_preload);
        free(cmd_send_fd);
    }
    else
    {
        printf("no command given.\n");
    }
    return 0;
}
