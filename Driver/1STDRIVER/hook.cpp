#include "hook.h"



__forceinline LPCSTR get_string(int index) {
	LPCSTR value = "";

	switch (index) {
	case 0: value = skCrypt_key("x64dbg", 432423, 2231); break;
	case 1: value = skCrypt_key("IDA: Quick start", 43223, 231); break;
	case 2: value = skCrypt_key("IDA -", 4324223, 22431); break;
	case 3: value = skCrypt_key("Scylla", 43423, 22231); break;
	case 4: value = skCrypt_key("Cheat Engine", 2423, 31); break;
	case 5: value = skCrypt_key("Process Hacker", 42423, 221); break;
	case 6: value = skCrypt_key("dnSpy", 43244323, 22131); break;
	case 7: value = skCrypt_key("ghidra", 43265423, 2223231); break;
	case 8: value = skCrypt_key("KsDumper", 43276423, 223321); break;
	case 9: value = skCrypt_key("dumper", 4313223, 2831); break;
	case 10: value = skCrypt_key("debugger", 43232423, 229831); break;
	case 11: value = skCrypt_key("HxD", 43762423, 234231); break;
	case 12: value = skCrypt_key("ReClass", 4324532423, 1); break;
	case 13: value = skCrypt_key("OllyDbg", 43422423, 228831); break;
	case 14: value = skCrypt_key("WdcWindow", 4322423, 22831); break;
	case 15: value = skCrypt_key("WinListerMain", 4326423, 223891); break;
	case 16: value = skCrypt_key("WinLister", 43242123, 22531); break;
	case 17: value = skCrypt_key("PROCHACKER", 4332423, 22631); break;
	case 18: value = skCrypt_key("dnspy", 4324243, 21231); break;
	case 19: value = skCrypt_key("Spy++", 43632423, 211231); break;
	case 99: value = skCrypt_key("C:\\Windows\\System32\\drivers\\lsass.exe", 43277423, 22381); break;
	case 143: value = skCrypt_key("win32u.dll", 4329423, 22131); break;
	case 145: value = skCrypt_key("NtQueryCompositionSurfaceStatistics", 4324023, 22301); break;
	case 146: value = skCrypt_key("b6b4477422792d20eaec1380a11edc89e038b1858b98c6ee36d4b616214df83d", 43002423, 20231); break;
	case 147: value = skCrypt_key("Iww3FYgxgE", 43200423, 22031); break;
	case 75534: value = skCrypt_key("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", 4300423, 2201); break;
	case 75774: value = skCrypt_key("NtSetCompositionSurfaceStatistics", 4399423, 2291); break;
	}

	return value;
}

bool hook::restore(ULONG windowsver)
{
	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export(get_string(75534), get_string(145))); // NtQueryCompositionSurfaceStatistics  NtRIMFreeInputBuffer NtSetCompositionSurfaceStatistics

	if (!function)
		return false;

	BYTE win10shellcode[] = { 0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x56, 0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48 };
	BYTE win11shellcode[] = { 0x48, 0x89, 0x5C, 0x24, 0x18, 0x57, 0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05 };

	if (windowsver == 10)
		write_to_read_only_memory(function, &win10shellcode, 16);
	else if (windowsver == 11)
		write_to_read_only_memory(function, &win11shellcode, 16);

	return true;
}

bool hook::call_kernel_function(void* kernel_function_address)
{
	if (!kernel_function_address)
		return false;
	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export(get_string(75534), get_string(145))); // NtQueryCompositionSurfaceStatistics  NtRIMFreeInputBuffer NtSetCompositionSurfaceStatistics

	if (!function)
		return false;
	
	uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address); // reinterpreting hook address
	BYTE assembl[16] = {
		0x50,                                                        // push rax
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, TARGET
		0x48, 0x87, 0x04, 0x24,                                      // xchg QWORD PTR[rsp], rax
		0xC3                                                         // retn
	};
	*(ULONGLONG*)(assembl + 3) = hook_address;

	write_to_read_only_memory(function, &assembl, sizeof(assembl));

	return true;
}

NTSTATUS hook::hook_handler(int check, SHORT check2, PVOID called_param)
{
	if (check != 40521 || check2 != 176)
			return STATUS_SUCCESS;

	COMMS_MEMORY* instructions = (COMMS_MEMORY*)called_param;

	if (instructions->read == TRUE)
	{
		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
		{
			SIZE_T Bytes;
			PEPROCESS process;
			if (PsLookupProcessByProcessId((HANDLE)instructions->pid, &process) != STATUS_SUCCESS)
				return STATUS_SUCCESS;
			if (MmCopyVirtualMemory(process, (PVOID)instructions->address, PsGetCurrentProcess(),
				instructions->output, instructions->size, KernelMode, &Bytes) != STATUS_SUCCESS)
				return STATUS_SUCCESS;
		}
	}

	else if (instructions->write == TRUE)
	{
		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
		{
			PEPROCESS process;
			if (PsLookupProcessByProcessId((HANDLE)instructions->pid, &process) != STATUS_SUCCESS)
				return STATUS_SUCCESS;

			SIZE_T Bytes;

			if (MmCopyVirtualMemory(PsGetCurrentProcess(), instructions->buff_address, process,
				(PVOID)instructions->address, instructions->size, KernelMode, &Bytes) != STATUS_SUCCESS)
				return STATUS_SUCCESS;
		}
	}
	else if (instructions->req_base == TRUE)
	{
		ANSI_STRING AS;
		UNICODE_STRING ModuleName;

		RtlInitAnsiString(&AS, instructions->module_name);
		RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

		PEPROCESS process;
		if (PsLookupProcessByProcessId((HANDLE)instructions->pid, &process) != STATUS_SUCCESS)
		{
			RtlFreeUnicodeString(&ModuleName);
			return STATUS_SUCCESS;
		}
		if (process != NULL)
		{
			PPEB pPeb = PsGetProcessPeb(process);

			if (!pPeb)
			{
				return false;
			}

			KAPC_STATE state;

			KeStackAttachProcess(process, &state);

			PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

			if (!pLdr)
			{
				KeUnstackDetachProcess(&state);
				return false;
			}

			for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink; list != &pLdr->InLoadOrderModuleList; list = (PLIST_ENTRY)list->Flink)
			{
				PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

				if (RtlCompareUnicodeString(&pEntry->BaseDllName, &ModuleName, TRUE) == NULL)
				{
					ULONG64 baseAddress = (ULONG64)pEntry->DllBase;
					ULONG64 ModuleSize = (ULONG64)pEntry->SizeOfImage;
					KeUnstackDetachProcess(&state);
					instructions->base_address = baseAddress;
					instructions->size = ModuleSize;
					return true;
				}
			}


			KeUnstackDetachProcess(&state);
			return true;
			RtlFreeUnicodeString(&ModuleName);
			return STATUS_SUCCESS;
		}
		else
			return STATUS_SUCCESS;
	}
	else if (instructions->antidebug == TRUE)
	{
		*(ULONG*)(&protected_pid) = instructions->pid;
	}
	

	/*else if (instructions->antidebug == TRUE)
	{
		instructions->address = 0;
		PEPROCESS process;
		if (instructions->check != 76542454 || instructions->base_address == 200)
		{
			_NtRaiseHardError NtRaiseHardError = (_NtRaiseHardError)get_system_module_export("ntdll.dll", "NtRaiseHardError");
				NtRaiseHardError(0xDEB, NULL, NULL, NULL, 6, NULL);
		}

		if (PsLookupProcessByProcessId((HANDLE)instructions->pid, &process) == STATUS_SUCCESS)
		{
			PPEB peb = PsGetProcessPeb(process);
			BYTE beingdebugged = peb->BeingDebugged;
			DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)peb + 0x68);
			if (beingdebugged == 1 || dwNtGlobalFlag == 0x70)
			{
				instructions->address = 101;
				_NtRaiseHardError NtRaiseHardError = (_NtRaiseHardError)get_system_module_export("ntdll.dll", "NtRaiseHardError");
				NtRaiseHardError(0xDEB, NULL, NULL, NULL, 6, NULL);
			}


			NtSetInformationThread((HANDLE)instructions->pid, ThreadHideFromDebugger, 0, 0);
		}
		CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		PETHREAD thread;
		if (PsLookupThreadByThreadId((HANDLE)instructions->pid, &thread) == STATUS_SUCCESS)
		{
			if (PsGetContextThread(thread, &ctx, KernelMode) == STATUS_SUCCESS)
			{
				if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
				{
					instructions->address = 101;
					_NtRaiseHardError NtRaiseHardError = (_NtRaiseHardError)get_system_module_export("ntdll.dll", "NtRaiseHardError");
					NtRaiseHardError(0xDEB, NULL, NULL, NULL, 6, NULL);
				}
			}
		}

		

	}*/


	return STATUS_SUCCESS;
}