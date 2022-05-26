#include <iostream>
#include <string>
#include <unistd.h>
#include "sdb.hpp"

using namespace std;

int main(int argc, char *argv[])
{
    const char *opt_sring = "s:";
    int option;
    string script = "", program = "";

    while ((option = getopt(argc, argv, opt_sring)) != -1)
    {
        switch (option)
        {
        case 's':
            script = optarg;
            break;
        default:
            break;
        }
    }
    if (argc > optind)
    {
        program = argv[optind];
    }
    processing(script, program);
    return 0;
}