#pragma once
#include "memory.h"
#include "skStr.h"
#include "globalvar.h"

namespace hook
{
	bool call_kernel_function(void* kernel_function_address);
	NTSTATUS hook_handler(int check, SHORT check2, PVOID called_param);
	bool restore(ULONG windowsver);
}