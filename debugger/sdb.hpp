#ifndef __SDB_HPP
#define __SDB_HPP
#include <iostream>
#include "string.h"
#include "vector"

typedef enum
{
    not_load,
    loaded,
    running,
    terminated,
} sdb_state;

typedef enum
{
    vm_region,
    vm_flags,
    vm_pgoff,
    vm_dev,
    vm_node,
    vm_path,
} vmmap_list;

typedef struct break_point
{
    unsigned long long int addr;
    int id;
    unsigned char orig_content;
} break_point;

using namespace std;

typedef void (*func_ptr)(vector<string> args);

void processing(string script, string program);

void set_bp(vector<string>);
void cont(vector<string>);
void delete_bp(vector<string>);
void disasm(vector<string>);
void dump(vector<string>);
void exit(vector<string>);
void get_reg(vector<string>);
void get_regs(vector<string>);
void help(vector<string>);
void list_bp(vector<string>);
void load(vector<string>);
void run(vector<string>);
void vmmap(vector<string>);
void set_reg(vector<string>);
void single_step(vector<string>);
void start(vector<string>);
#endif