#include <iostream>
#include <fstream>
#include "string.h"
#include "stdio.h"
#include "vector"
#include <map>
#include <assert.h>
#include <sstream>
#include "sdb.hpp"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

using namespace std;

map<string, func_ptr> commands;
sdb_state state = not_load;
unsigned long entry_point = 0;
string running_program = "";
static const string state_name[] = {"not_load", "loaded", "running"};
struct user_regs_struct regs;
char *null_argv[] = {NULL};
pid_t pid;

#define check_state(_state)                                                                                          \
    if (_state != state)                                                                                             \
    {                                                                                                                \
        cout << "** This command is valid for: " << #_state << " ,but current state: " << state_name[state] << endl; \
        return;                                                                                                      \
    }

static void init_commands()
{
    commands["break"] = commands["b"] = &set_bp;
    commands["cont"] = commands["c"] = &cont;
    commands["delete"] = &delete_bp;
    commands["disasm"] = &disasm;
    commands["dump"] = commands["x"] = &dump;
    commands["exit"] = commands["q"] = &exit;
    commands["get"] = commands["g"] = &get_reg;
    commands["getregs"] = &get_regs;
    commands["help"] = commands["h"] = &help;
    commands["list"] = commands["l"] = &list_bp;
    commands["load"] = &load;
    commands["run"] = commands["r"] = &run;
    commands["vmmap"] = commands["m"] = &vmmap;
    commands["set"] = commands["s"] = &set_bp;
    commands["si"] = &single_step;
    commands["start"] = &start;
}
static inline void call_command(vector<string> argv)
{
    auto iter = commands.find(argv[0]);
    if (iter != commands.end())
    {

        iter->second(argv);
    }
    else
    {
        cout << "** command '" << argv[0] << "' not found\n";
    }
}
static vector<string> split_argv(string line)
{
    vector<string> ret;
    stringstream ss(line);
    string arg;
    while (ss >> arg)
    {
        ret.push_back(arg);
    }
    return ret;
}
static inline void errquit(const char *msg)
{
    perror(msg);
    exit(-1);
}

/* implementation of sdb's using */
void set_bp(vector<string>)
{
    cout << "in set_bp";
}
void cont(vector<string>) {}
void delete_bp(vector<string>) {}
void disasm(vector<string>)
{
    cout << "in disasm\n";
}
void dump(vector<string> argv) {}
void exit(vector<string> argv) {}
void get_reg(vector<string> argv) {}
void get_regs(vector<string> argv) {}
void help(vector<string> argv)
{
    cout << "- break {instruction-address}: add a break point\n";
    cout << "- cont: continue execution\n";
    cout << "- delete {break-point-id}: remove a break point\n";
    cout << "- disasm addr: disassemble instructions in a file or a memory region\n";
    cout << "- dump addr: dump memory content\n";
    cout << "- exit: terminate the debugger\n";
    cout << "- get reg: get a single value from a register\n";
    cout << "- getregs: show registers\n";
    cout << "- help: show this message\n";
    cout << "- list: list break points\n";
    cout << "- load {path/to/a/program}: load a program\n";
    cout << "- run: run the program\n";
    cout << "- vmmap: show memory layout\n";
    cout << "- set reg val: get a single value to a register\n";
    cout << "- si: step into instruction\n";
    cout << "- start: start the program and stop at the first instruction\n";
}
void list_bp(vector<string> argv) {}
void load(vector<string> argv)
{
    if (state != not_load)
    {
        printf("** The program has alreay been load. entry point 0x%lx", entry_point);
        return;
    }
    running_program = argv[1];
    if ((pid = fork()) < 0)
    {
        cout << "**[load] fail to fork\n";
        return;
    }
    if (pid == 0)
    { // child
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
        {
            errquit("** [load] traceme\n");
        }
        execvp(running_program.c_str(), null_argv);
        errquit("** [load] execvp\n");
    }
    else
    { // parent
        int status;
        if (waitpid(pid, &status, 0) < 0)
        {
            errquit("** [load] waitpid");
        }
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

        unsigned long long int rip;
        if ((rip = ptrace(PTRACE_PEEKUSER, pid, ((unsigned char *)&regs.rip) - ((unsigned char *)&regs), 0)) == 0)
        {
            errquit("** [load] peekuser\n");
        }
        printf("** program '%s' loaded. entry point 0x%llx\n", running_program.c_str(), rip);
    }
}
void run(vector<string> argv) {}
void vmmap(vector<string> argv) {}
void set_reg(vector<string> argv) {}
void single_step(vector<string> argv) {}
void start(vector<string> argv)
{
    cout << "in start\n";
}

void processing(string script, string program)
{
    init_commands();
    ifstream script_if(script);
    vector<string> commands;
    bool is_from_script = false, is_load = program != "" ? true : false;
    if (script != "")
    {
        if (!script_if.is_open())
        {
            cout << "** open script from " << script << " fail !\n";
            return;
        }
        is_from_script = true;
    }
    if (is_load)
    {
        call_command({"load", program});
    }

    while (true)
    {
        if (!is_from_script)
        {
            cout << "sdb> ";
        }
        string cmd;
        if (!getline(is_from_script ? script_if : cin, cmd))
        {
            break;
        }
        vector<string> argv = split_argv(cmd);
        if (!argv.size())
        {
            continue;
        }
        call_command(argv);
    }
}