#include "elf64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>

#define UNDEFINED_FUNC -1
#define FUNC_DEFINED_IN_ANOTHER_FILE 0
#define UND 0
#define FUNC_INDEX 1
#define STB_GLOBAL 1
#define FUNC_DEFINED_IN_THIS_FILE_GLOBALY 1
#define PROG_INDEX 2
#define ET_EXEC 2
#define SHT_SYMTAB 2
#define PLT_OFFSET 6
#define SHT_DYNSYM 11


/*
Questions:
1. does rela.plt need addend field?
*/



Elf64_Ehdr* getElfHeader(char* prog_name, FILE** fptr);
void deleteElfHeader(Elf64_Ehdr* file_header, FILE** fptr);
bool isFileExecutable(Elf64_Ehdr* file_header);
unsigned int getSectionHeaderSymbleTableIndex(Elf64_Ehdr* file_header, FILE** fptr, int symble_table_type);
int getSymbolIndexInSymTable(Elf64_Ehdr* file_header, FILE** fptr, char* func_name, int symble_table_type);
bool isSymbolGlobal(Elf64_Ehdr* file_header, FILE** fptr, int symbol_index, int symble_table_type);
bool isSymbolDefinedInAnotheFile(Elf64_Ehdr* file_header, FILE** fptr, int symbol_index, int symble_table_type);
unsigned long getFuncAddressFromThisFile(Elf64_Ehdr* file_header, FILE** fptr, int symbol_index);
unsigned long getFuncAddressDynamicaly(Elf64_Ehdr* file_header, FILE** fptr, int symbol_index);
pid_t run_target(char* argv[], Elf64_Ehdr* file_header, FILE** fptr);
void run_debugger(pid_t child_pid, unsigned long func_address, Elf64_Ehdr* file_header, FILE** fptr, bool is_dynamic);
void run_debugger2(pid_t child_pid, unsigned long func_address, Elf64_Ehdr* file_header, FILE** fptr);

int main(int argc, char* argv[])
{
    FILE *fptr = NULL;
    char* func_name = argv[FUNC_INDEX];
    char* prog_to_run_name = argv[PROG_INDEX];
    Elf64_Ehdr* file_header = getElfHeader(prog_to_run_name, &fptr);
    unsigned long func_address = 0;
    bool is_dynamic = false;
    if(!isFileExecutable(file_header))
    {
	printf("PRF:: %s not an executable! :(\n", prog_to_run_name);
    	deleteElfHeader(file_header, &fptr);
    	return 0;	
    }
    int func_symbol_index = getSymbolIndexInSymTable(file_header, &fptr, func_name, SHT_SYMTAB);
    if(func_symbol_index == UNDEFINED_FUNC)
    {
    	printf("PRF:: %s not found!\n", func_name);
	deleteElfHeader(file_header, &fptr);
    	return 0;
    }
    if(!isSymbolGlobal(file_header, &fptr, func_symbol_index, SHT_SYMTAB))
    {
	printf("PRF:: %s is not a global symbol! :(\n", func_name);
	deleteElfHeader(file_header, &fptr);
    	return 0;
    }
    if(isSymbolDefinedInAnotheFile(file_header, &fptr, func_symbol_index, SHT_SYMTAB))
    {
	func_symbol_index = getSymbolIndexInSymTable(file_header, &fptr, func_name, SHT_DYNSYM);
        func_address = getFuncAddressDynamicaly(file_header, &fptr, func_symbol_index);
	is_dynamic = true;
    }
    else
    {
	func_address = getFuncAddressFromThisFile(file_header, &fptr, func_symbol_index);
    }
    pid_t child_pid;
    child_pid = run_target(argv, file_header, &fptr);
    run_debugger(child_pid, func_address, file_header, &fptr, is_dynamic);
    deleteElfHeader(file_header, &fptr);
    return 0;
}

Elf64_Ehdr* getElfHeader(char* prog_name, FILE** fptr)
{
    Elf64_Ehdr *file_header = malloc(sizeof(Elf64_Ehdr));
    if (file_header == NULL)
    {
        exit(1);
    }
    *fptr = fopen(prog_name,"r");

    if (*fptr == NULL)
    {
	free(file_header);
        exit(1);
    }
    fread(file_header, sizeof(Elf64_Ehdr), 1, *fptr);
    return file_header;
}

void deleteElfHeader(Elf64_Ehdr* file_header, FILE** fptr)
{
    free(file_header);
    fclose(*fptr);
}

bool isFileExecutable(Elf64_Ehdr* file_header)
{
    if (file_header->e_type != ET_EXEC)
    {
	return false;
    }
    return true;
}

int getSymbolIndexInSymTable(Elf64_Ehdr* file_header, FILE** fptr, char* func_name, int symble_table_type)
{
    unsigned int symtab_section_header_index = getSectionHeaderSymbleTableIndex(file_header, fptr, symble_table_type);
    Elf64_Shdr* section_header_symtab = malloc(sizeof(Elf64_Shdr));
    if(section_header_symtab == NULL)
    {
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }
    fseek(*fptr, file_header->e_shoff + file_header->e_shentsize * symtab_section_header_index, SEEK_SET);
    fread(section_header_symtab, sizeof(Elf64_Shdr), 1, *fptr);
    unsigned int strtab_section_index = section_header_symtab->sh_link;
    Elf64_Shdr* section_header_strtab = malloc(sizeof(Elf64_Shdr));
    if(section_header_strtab == NULL)
    {
	free(section_header_symtab);
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }
    fseek(*fptr, file_header->e_shoff  + file_header->e_shentsize * strtab_section_index , SEEK_SET);
    fread(section_header_strtab, sizeof(Elf64_Shdr), 1, *fptr);
    unsigned long long string_table_size = section_header_strtab->sh_size;

    char * string_table = malloc(string_table_size);
    if(string_table == NULL)
    {
	free(section_header_symtab);
	free(section_header_strtab);
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }
    fseek(*fptr, section_header_strtab->sh_offset , SEEK_SET);
    fread(string_table, string_table_size, 1, *fptr);
    if(section_header_symtab->sh_entsize == 0)
    {
	free(section_header_symtab);
	free(section_header_strtab);
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }
    int symtab_num_of_entries = section_header_symtab->sh_size / section_header_symtab->sh_entsize;
    Elf64_Sym* symtab_entry = malloc(sizeof(*symtab_entry));
    if(symtab_entry == NULL)
    {
	free(section_header_symtab);
	free(section_header_strtab);
    	free(file_header);
	free(string_table);
    	fclose(*fptr);
        exit(1);
    }
    for(int i = 0; i < symtab_num_of_entries; i++)
    {
        fseek(*fptr, section_header_symtab->sh_offset + section_header_symtab->sh_entsize * i, SEEK_SET);
        fread(symtab_entry, sizeof(*symtab_entry), 1, *fptr);
        if(strcmp(string_table + symtab_entry->st_name, func_name) == 0)
        {
            free(section_header_symtab);
	    free(section_header_strtab);
	    free(symtab_entry);
	    free(string_table);
            return i;
        }
    }
    free(section_header_symtab);
    free(section_header_strtab);
    free(symtab_entry);
    free(string_table);
    return UNDEFINED_FUNC;
}

unsigned int getSectionHeaderSymbleTableIndex(Elf64_Ehdr* file_header, FILE** fptr, int symble_table_type)
{
    unsigned int symtab_section_index = 0;
    Elf64_Shdr* section_header_symtab = malloc(sizeof(Elf64_Shdr));
    if(section_header_symtab == NULL)
    {
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }

    for(unsigned int i=0; i < file_header->e_shnum; i++)
    {
        fseek(*fptr, file_header->e_shoff + file_header->e_shentsize * i , SEEK_SET);
        fread(section_header_symtab, sizeof(Elf64_Shdr), 1, *fptr);
        if(section_header_symtab->sh_type == symble_table_type)
        {
	    symtab_section_index = i;
            break;
        }
    }
    free(section_header_symtab);
    return symtab_section_index;
}

bool isSymbolGlobal(Elf64_Ehdr* file_header, FILE** fptr, int symbol_index, int symble_table_type)
{
    Elf64_Shdr* section_header_symtab = malloc(sizeof(Elf64_Shdr));
    if(section_header_symtab == NULL)
    {
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }
    int symtab_section_header_index = getSectionHeaderSymbleTableIndex(file_header, fptr, symble_table_type);
    fseek(*fptr, file_header->e_shoff + file_header->e_shentsize * symtab_section_header_index, SEEK_SET);
    fread(section_header_symtab, sizeof(Elf64_Shdr), 1, *fptr);
    
    Elf64_Sym* symtab_entry = malloc(sizeof(*symtab_entry));
    if(symtab_entry == NULL)
    {
	free(section_header_symtab);
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }

    fseek(*fptr, section_header_symtab->sh_offset + section_header_symtab->sh_entsize * symbol_index, SEEK_SET);
    fread(symtab_entry, sizeof(*symtab_entry), 1, *fptr);
    if(ELF64_ST_BIND(symtab_entry->st_info) != STB_GLOBAL)
    {
    	free(section_header_symtab);
    	free(symtab_entry);
	return false;
    }
    free(section_header_symtab);
    free(symtab_entry);
    return true;
}

bool isSymbolDefinedInAnotheFile(Elf64_Ehdr* file_header, FILE** fptr, int symbol_index, int symble_table_type)
{
    Elf64_Shdr* section_header_symtab = malloc(sizeof(Elf64_Shdr));
    if(section_header_symtab == NULL)
    {
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }
    int symtab_section_header_index = getSectionHeaderSymbleTableIndex(file_header, fptr, symble_table_type);
    fseek(*fptr, file_header->e_shoff + file_header->e_shentsize * symtab_section_header_index, SEEK_SET);
    fread(section_header_symtab, sizeof(Elf64_Shdr), 1, *fptr);
    
    Elf64_Sym* symtab_entry = malloc(sizeof(*symtab_entry));
    if(symtab_entry == NULL)
    {
	free(section_header_symtab);
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }

    fseek(*fptr, section_header_symtab->sh_offset + section_header_symtab->sh_entsize * symbol_index, SEEK_SET);
    fread(symtab_entry, sizeof(*symtab_entry), 1, *fptr);
    if(symtab_entry->st_shndx == UND)
    {
    	free(section_header_symtab);
    	free(symtab_entry);
    	return true;
    }
    free(section_header_symtab);
    free(symtab_entry);
    return false;
}

unsigned long getFuncAddressFromThisFile(Elf64_Ehdr* file_header, FILE** fptr, int symbol_index)
{
    unsigned long func_address = 0;
    Elf64_Shdr* section_header_symtab = malloc(sizeof(Elf64_Shdr));
    if(section_header_symtab == NULL)
    {
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }
    int symtab_section_header_index = getSectionHeaderSymbleTableIndex(file_header, fptr, SHT_SYMTAB);
    fseek(*fptr, file_header->e_shoff + file_header->e_shentsize * symtab_section_header_index, SEEK_SET);
    fread(section_header_symtab, sizeof(Elf64_Shdr), 1, *fptr);
    
    Elf64_Sym* symtab_entry = malloc(sizeof(*symtab_entry));
    if(symtab_entry == NULL)
    {
	free(section_header_symtab);
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }

    fseek(*fptr, section_header_symtab->sh_offset + section_header_symtab->sh_entsize * symbol_index, SEEK_SET);
    fread(symtab_entry, sizeof(*symtab_entry), 1, *fptr);
    func_address = symtab_entry->st_value;
    return func_address;
}

unsigned long getFuncAddressDynamicaly(Elf64_Ehdr* file_header, FILE** fptr, int symbol_index)
{
    unsigned long func_address = 0;
    Elf64_Shdr* section_header_shtstrtab = malloc(sizeof(Elf64_Shdr));
    if(section_header_shtstrtab == NULL)
    {
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }

    fseek(*fptr, file_header->e_shoff + file_header->e_shentsize * file_header->e_shstrndx, SEEK_SET);
    fread(section_header_shtstrtab, sizeof(Elf64_Shdr), 1, *fptr);

    char* sh_str_tab = malloc(section_header_shtstrtab->sh_size);
    if(sh_str_tab == NULL)
    {
	free(section_header_shtstrtab);
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }

    fseek(*fptr, section_header_shtstrtab->sh_offset , SEEK_SET);
    fread(sh_str_tab, section_header_shtstrtab->sh_size, 1, *fptr);
    
    Elf64_Shdr* sh_entry = malloc(file_header->e_shentsize);
    if(sh_entry == NULL)
    {
	free(sh_str_tab);
	free(section_header_shtstrtab);
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }

    for(int i = 0; i < file_header->e_shnum; i++)
    {
        fseek(*fptr, file_header->e_shoff + file_header->e_shentsize * i, SEEK_SET);
        fread(sh_entry, file_header->e_shentsize, 1, *fptr);
        if(strcmp(sh_str_tab + sh_entry->sh_name, ".rela.plt") == 0)
        {
	    break;
        }
    }
    if(sh_entry->sh_entsize == 0)
    {
	free(sh_str_tab);
	free(section_header_shtstrtab);
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }
    int num_of_rela_entries = sh_entry->sh_size / sh_entry->sh_entsize;
    Elf64_Rela* rela_entry = malloc(sh_entry->sh_entsize);
    if(rela_entry == NULL)
    {
	free(sh_entry);
        free(sh_str_tab);
	free(section_header_shtstrtab);
    	free(file_header);
    	fclose(*fptr);
        exit(1);
    }

    for(int i = 0; i < num_of_rela_entries; i++)
    {
        fseek(*fptr, sh_entry->sh_offset + sh_entry->sh_entsize * i, SEEK_SET);
        fread(rela_entry, sh_entry->sh_entsize, 1, *fptr);
        if(ELF64_R_SYM(rela_entry->r_info) == symbol_index)
        {
	    func_address = rela_entry->r_offset;
	    break;
        }
    }
    free(sh_entry);
    free(sh_str_tab);
    free(section_header_shtstrtab);
    free(rela_entry);
    return func_address;
}

pid_t run_target(char* argv[], Elf64_Ehdr* file_header, FILE** fptr)
{
    pid_t pid;
    pid = fork();
    if(pid > 0)
    {
	return pid;
    }
    else if(pid == 0)
    {
  	if(ptrace(PTRACE_TRACEME, 0 , NULL, NULL) < 0)
	{
    	    free(file_header);
    	    fclose(*fptr);
	    exit(1);
	}
	execv((argv+2)[0], (argv+2));
    }
    else
    {
	free(file_header);
        fclose(*fptr);
        exit(1);
    }
}


void run_debugger(pid_t child_pid, unsigned long func_address, Elf64_Ehdr* file_header, FILE** fptr, bool is_dynamic)
{
    int counter = 0;
    int wait_status;
    struct user_regs_struct regs;
    
    wait(&wait_status);
    if(!WIFSTOPPED(wait_status))
    {
	return;
    }
    unsigned long address = func_address;
    long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)address,NULL);
    if(is_dynamic)
    {
        address = data - PLT_OFFSET;
        data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)address,NULL);
    }    

    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)address, (void*)data_trap);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);  
    wait(&wait_status);
    if(!WIFSTOPPED(wait_status))
    {
	return;
    }
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    ptrace(PTRACE_POKETEXT, child_pid, (void*)address, (void*)data);
    regs.rip -= 1;
    long return_address_from_func = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rsp, NULL);
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

    data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)return_address_from_func,NULL);
    data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address_from_func, (void*)data_trap);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);

    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address_from_func, (void*)data);
    regs.rip -= 1;    
    counter++;
    int ret_value = regs.rax;
    printf("PRF:: run #%d returned with %d\n", counter, ret_value);
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
    if(is_dynamic)
    {
	address = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_address,NULL);
    }
    data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)address,NULL);
    data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)address, (void*)data_trap);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);
    while(WIFSTOPPED(wait_status))
   {
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    ptrace(PTRACE_POKETEXT, child_pid, (void*)address, (void*)data);
    regs.rip -= 1;
    return_address_from_func = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rsp, NULL);
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

    data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)return_address_from_func,NULL);
    data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address_from_func, (void*)data_trap);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address_from_func, (void*)data);
    regs.rip -= 1;    
    counter++;
    ret_value = regs.rax;
    printf("PRF:: run #%d returned with %d\n", counter, ret_value);
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
    data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)address,NULL);
    data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)address, (void*)data_trap);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);
   }
}