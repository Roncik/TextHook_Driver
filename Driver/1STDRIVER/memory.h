#pragma once
#include "definitions.h"
#include "nt_defines.hpp"
#include "globalvar.h"
typedef struct _COMMS_MEMORY
{
	void*		buff_address;
	ULONGLONG	size;
	UINT_PTR	address;
	int			check;
	BOOLEAN		write, read, req_base, antidebug;
	ULONG		pid;
	void*		output;
	const char* module_name;
	ULONG64		base_address;
}COMMS_MEMORY;

PVOID	get_system_module_base(const char* module_name);
PVOID	get_system_module_export(const char* module_name, LPCSTR routine_name);
bool	write_memory(void* address, void* buffer, size_t size);
bool	write_to_read_only_memory(void* address, void* buffer, size_t size);
bool	get_module_base_x64(PEPROCESS proc, UNICODE_STRING module_name, COMMS_MEMORY* towrite);
bool	read_kernel_memory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);
bool	write_kernel_memory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);



