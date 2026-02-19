#include "codecave.hpp"
#include "hook.h"



#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (ULONG_PTR)(&((type *)0)->field)))
#define EACSLEEP

NTSTATUS Sleep(ULONGLONG milliseconds)
{
	LARGE_INTEGER delay;
	ULONG* split;

	milliseconds *= 1000000;

	milliseconds /= 100;

	milliseconds = -milliseconds;

	split = (ULONG*)&milliseconds;

	delay.LowPart = *split;

	split++;

	delay.HighPart = *split;


	KeDelayExecutionThread(KernelMode, 0, &delay);

	return STATUS_SUCCESS;
}

PVOID GetSystemRoutineAddress(LPCWSTR name)
{
    UNICODE_STRING unicodeName;
    RtlInitUnicodeString(&unicodeName, name);
    return MmGetSystemRoutineAddress(&unicodeName);
}

PVOID GetSystemModuleBase(LPCWSTR name)
{
    PLIST_ENTRY loadedModuleList = (PLIST_ENTRY)(GetSystemRoutineAddress(L"PsLoadedModuleList"));
    if (!loadedModuleList)
    {
        return NULL;
    }
    __try
    {
        for (PLIST_ENTRY link = loadedModuleList->Flink; link != loadedModuleList; link = link->Flink)
        {
            LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (_wcsicmp(name, entry->BaseDllName.Buffer) == 0)
            {
                return entry->DllBase;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }
    return NULL;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING reg_path)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(reg_path);
    

    if (GetSystemModuleBase(L"EasyAntiCheat.sys") != NULL)
    {
        return STATUS_SUCCESS;
    }

    //DbgPrintEx(0, 0, "Start\n");

    void* module_list = get_module_list();
    if (!module_list) return STATUS_UNSUCCESSFUL;
    RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)module_list;

    // First module is always ntoskrnl.exe
    RTL_PROCESS_MODULE_INFORMATION* module = &modules->Modules[0];

    QWORD address = find_pattern_nt("48 8B C4 48 89 58 08 48 89 70 18 57 48 83 EC 20 33 F6", (QWORD)module->ImageBase, module->ImageSize);
    if (!address)
    {
        address = find_pattern_nt("48 89 5C 24 08 48 89 6C 24 18 48 89 74 24 20 57 48 83 EC 20 33 ED", (QWORD)module->ImageBase, module->ImageSize);
        if (!address)
        {
            //DbgPrintEx(0, 0, "[-] Could not find MiLookupDataTableEntry\n");
            return STATUS_UNSUCCESSFUL;
        }
    }
    //DbgPrintEx(0, 0, "[+] Found MiLookupDataTableEntry at 0x%p\n", (VOID*)address);
    MiLookupDataTableEntry = (MiLookupDataTableEntry_fn)address;

    ExFreePool(module_list);
    if (!apply_codecaves())
    {
        //DbgPrintEx(0, 0, "[-] Failed applying code caves\n");
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS regstatus = ReadRegistryDword(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\keybd", L"Param1", (DWORD*)&protected_pid);

#ifdef EACSLEEP
    //DbgPrintEx(0, 0, "Running\n");
    
    RTL_OSVERSIONINFOW osvi = { 0 };

    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (RtlGetVersion(&osvi) == 0) 
    {
        if (osvi.dwBuildNumber < 22000)
        {
            //DbgPrintEx(0, 0, "Restored 10\n");
            hook::restore(10);
        }
        else if (osvi.dwBuildNumber >= 22000)
        {
            //DbgPrintEx(0, 0, "Restored 11\n");
            hook::restore(11);
        }
    }
    
    //DbgPrintEx(0, 0, "Looking for EAC\n");
    while (true)
    {
        if (GetSystemModuleBase(L"EasyAntiCheat.sys"))
            break;
    }
    //DbgPrintEx(0, 0, "Found EAC\n");

	Sleep(30000);


#endif

	hook::call_kernel_function(&hook::hook_handler);

	return STATUS_SUCCESS;
}