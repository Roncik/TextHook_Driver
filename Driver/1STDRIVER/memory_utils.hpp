#pragma once

#include <ntifs.h>
#include <intrin.h>
#include <ntddk.h>
#include <windef.h>
#include <cstdint>
#include <ntimage.h>
#include <cstdint>
#include <cstddef>
#include <ntdef.h>
#include <ntstrsafe.h>
#include <handleapi.h>
#include <winioctl.h>

#include "definitions.h"
#include "nt_defines.hpp"
#include "globalvar.h"




typedef unsigned long long QWORD;

static UINT64 _be_pre_ob_callback_cave = 0;
const WCHAR driver_name[] = L"iorate.sys";
const CHAR driver_name_c[] = "iorate.sys";



PVOID g_CallbackHandle = NULL;



//define credits: learn_more
#define INRANGE(x,a,b)  (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))



static QWORD find_pattern_nt(_In_ CONST CHAR* sig, _In_ QWORD start, _In_ QWORD size)
{
	QWORD match = 0;
	const char* pat = sig;

	for (QWORD cur = start; cur < (start + size); ++cur)
	{
        if (MmIsAddressValid((PVOID)cur))
        {
            if (!*pat) return match;

            else if (*(BYTE*)pat == '\?' || *(BYTE*)cur == getByte(pat))
            {
                if (!match) match = cur;

                if (!pat[2]) return match;

                else if (*(WORD*)pat == '\?\?' || *(BYTE*)pat != '\?') pat += 3;
                else pat += 2;
            }

            else
            {
                pat = sig;
                match = 0;
            }
        }
	}

	return 0;
}

static BOOLEAN is_retop(_In_ BYTE op)
{
	return op == 0xC2 ||   // RETN + POP
		op == 0xC3 ||      // RETN
		op == 0xCA ||      // RETF + POP
		op == 0xCB;        // RETF
}

/*
	Finds a suitable length code cave inside the .text section of the given module
	A valid code cave is a sequence of CC bytes prefixed by a return statement
*/
static QWORD find_codecave(_In_ VOID* module, _In_ INT length, _In_opt_ QWORD begin)
{
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module;
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)dos_header + dos_header->e_lfanew);
	
	QWORD start = 0, size = 0;

	QWORD header_offset = (QWORD)IMAGE_FIRST_SECTION(nt_headers);
	for (INT x = 0; x < nt_headers->FileHeader.NumberOfSections; ++x)
	{
		IMAGE_SECTION_HEADER* header = (IMAGE_SECTION_HEADER*)header_offset;

		if (strcmp((CHAR*)header->Name, ".text") == 0)
		{
			start = (QWORD)module + header->PointerToRawData;
			size = header->SizeOfRawData;
			break;
		}

		header_offset += sizeof(IMAGE_SECTION_HEADER);
	}

	QWORD match = 0;
	INT curlength = 0;
	BOOLEAN ret = FALSE;

	for (QWORD cur = (begin ? begin : start); cur < start + size; ++cur)
	{
		if (!ret && is_retop(*(BYTE*)cur)) ret = TRUE;
		else if (ret && *(BYTE*)cur == 0xCC)
		{
			if (!match) match = cur;
			if (++curlength == length) return match;
		}

		else
		{
			match = curlength = 0;
			ret = FALSE;
		}
	}

	return 0;
}

/*
	Remaps the page where the target address is in with PAGE_EXECUTE_READWRITE protection and patches in the given bytes
	If this is the restore routine, then after patching in the bytes the protection is set back to PAGE_READONLY
*/
static BOOLEAN remap_page(_In_ VOID* address, _In_ BYTE* assembly, _In_ ULONG length, _In_ BOOLEAN restore)
{
	MDL* mdl = IoAllocateMdl(address, length, FALSE, FALSE, 0);
	if (!mdl)
	{
        DbgPrint("[-] Failed allocating MDL!\n"); 
		return FALSE;
	}

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

	VOID* map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
	if (!map_address)
	{
        DbgPrint("[-] Failed mapping the page!\n");
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
	if (status)
	{
        DbgPrint("[-] Failed MmProtectMdlSystemAddress with status: 0x%lX\n", status);
		MmUnmapLockedPages(map_address, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	RtlCopyMemory(map_address, assembly, length);

	if (restore)
	{
		status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
		if (status)
		{
            DbgPrint("[-] Failed second MmProtectMdlSystemAddress with status: 0x%lX\n", status);
			MmUnmapLockedPages(map_address, mdl);
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			return FALSE;
		}
	}

	MmUnmapLockedPages(map_address, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return TRUE;
}

static BOOLEAN patch_codecave_detour(_In_ QWORD address, _In_ QWORD target)
{
	BYTE assembly[16] = {
		0x50,                                                        // push rax
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, TARGET
		0x48, 0x87, 0x04, 0x24,                                      // xchg QWORD PTR[rsp], rax
		0xC3                                                         // retn
	};
	*(QWORD*)(assembly + 3) = target;

	return remap_page((VOID*)address, assembly, 16, FALSE);
}

static BOOLEAN restore_codecave_detour(_In_ QWORD address)
{
	BYTE assembly[16] = {
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
	};

	return remap_page((VOID*)address, assembly, 16, TRUE);
}

static VOID to_lower(_In_ CHAR* in, _Out_ CHAR* out)
{
	INT i = -1;
	while (in[++i] != '\x00') out[i] = (CHAR)tolower(in[i]);
}

static BOOLEAN is_pg_protected(_In_ CONST CHAR* image)
{
	
	static CONST CHAR* images[] = { "win32kbase.sys", "tm.sys", "clfs.sys", "msrpc.sys", "ndis.sys", "ntfs.sys", "tcpip.sys", "fltmgr.sys", "ksecdd.sys", "clipsp.sys", "cng.sys", "dxgkrnl.sys"};
	static INT count = 12;

	for (INT i = 0; i < count; ++i)
	{
		if (strstr(image, images[i]))
			return TRUE;
	}

	return FALSE;
}

//static BOOLEAN is_pg_protected(_In_ CONST CHAR* image)
//{
//	INT result = strstr(image, "puz15");
//
//	if (result == 0)
//	{
//		return TRUE;
//	}
//
//	return FALSE;
//}

#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define POOLTAG 'EB'

typedef unsigned long long QWORD;
#define ABSOLUTE(wait)			(wait)
#define RELATIVE(wait)			(-(wait))
#define NANOSECONDS(nanos)		(((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros)	(((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli)		(((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds)		(((signed __int64)(seconds)) * MILLISECONDS(1000L))

namespace Utils
{
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

    void WriteProtectOff()
    {
        auto cr0 = __readcr0();
        cr0 &= 0xfffffffffffeffff;
        __writecr0(cr0);
        _disable();
    }

    void WriteProtectOn()
    {
        auto cr0 = __readcr0();
        cr0 |= 0x10000;
        _enable();
        __writecr0(cr0);
    }

    bool is_pg_protected(const char* image)
    {
        static CONST CHAR* images[] = { "win32kbase.sys", "tm.sys", "clfs.sys", "msrpc.sys", "ndis.sys", "ntfs.sys", "fltmgr.sys", "clipsp.sys", "cng.sys", "Wdf01000.sys", "WppRecorder.sys", "SleepStudyHelper.sys", "acpiex.sys", "ACPI.sys", "pci.sys", "tpm.sys", "intelpep.sys", "WindowsTrustedRT.sys", "pdc.sys", "CEA.sys", "partmgr.sys", "spaceport.sys", "volmgr.sys", "volmgrx.sys", "mountmgr.sys", "storahci.sys", "storport.sys", "hall.dll", "kd.dll", "ksecdd.sys", "stornvme.sys", "EhStorClass.sys", "fileinfo.sys", "Wof.sys", "Ntfs.sys", "ksecpkg.sys", "tcpip.sys", "fwpkclnt.sys", "wfplwfs.sys", "fvevol.sys", "volsnap.sys", "rdyboost.sys", "mup.sys", "iorate.sys" };
        for (INT i = 0; i < 44; ++i)
        {
            if (strstr(image, images[i]))
            {
                return TRUE;
            }
        }
        return FALSE;
    }

    PVOID GetDriverBase(LPCSTR module_name)
    {
        ULONG bytes{};
        NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);
        if (!bytes)
        {
            return NULL;
        }
        PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, POOLTAG);
        if (modules)
        {
            status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
            if (!NT_SUCCESS(status))
            {
                ExFreePoolWithTag(modules, POOLTAG);
                return NULL;
            }
            PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
            PVOID module_base{}, module_size{};
            for (ULONG i = 0; i < modules->NumberOfModules; i++)
            {
                if (strcmp(reinterpret_cast<char*>(module[i].FullPathName + module[i].OffsetToFileName), module_name) == 0)
                {
                    module_base = module[i].ImageBase;
                    module_size = (PVOID)module[i].ImageSize;
                    break;
                }
            }
            ExFreePoolWithTag(modules, POOLTAG);
            return module_base;
        }
        return NULL;
    }

    static BOOLEAN is_retop(_In_ BYTE op)
    {
        return op == 0xC2 || op == 0xC3 || op == 0xCA || op == 0xCB;
    }

    static QWORD find_codecave(_In_ VOID* module, _In_ INT length)
    {
        IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module;
        IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)dos_header + dos_header->e_lfanew);
        QWORD start = 0, size = 0;

        QWORD header_offset = (QWORD)IMAGE_FIRST_SECTION(nt_headers);
        for (INT x = 0; x < nt_headers->FileHeader.NumberOfSections; ++x)
        {
            IMAGE_SECTION_HEADER* header = (IMAGE_SECTION_HEADER*)header_offset;

            if (strcmp((CHAR*)header->Name, ".text") == 0)
            {
                start = (QWORD)module + header->PointerToRawData;
                size = header->SizeOfRawData;
                break;
            }
            header_offset += sizeof(IMAGE_SECTION_HEADER);
        }
        QWORD match = 0;
        INT curlength = 0;
        BOOLEAN ret = FALSE;

        for (QWORD cur = start; cur < start + size; ++cur)
        {
            if (!ret && is_retop(*(BYTE*)cur))
            {
                ret = TRUE;
            }
            else if (ret && *(BYTE*)cur == 0xCC)
            {
                if (!match) match = cur;
                if (++curlength == length) return match;
            }
            else
            {
                match = curlength = 0;
                ret = FALSE;
            }
        }
        return 0;
    }

    static BOOLEAN remap_page(_In_ VOID* address, _In_ BYTE* assembly, _In_ ULONG length, _In_ BOOLEAN restore)
    {
        MDL* mdl = IoAllocateMdl(address, length, FALSE, FALSE, 0);
        if (!mdl)
        {
            DbgPrint("[-] Failed allocating MDL!\n");
            return FALSE;
        }

        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

        VOID* map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
        if (!map_address)
        {
            DbgPrint("[-] Failed mapping the page!\n");
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }

        NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
        if (status)
        {
            DbgPrint("[-] Failed MmProtectMdlSystemAddress with status: 0x%lX\n", status);
            MmUnmapLockedPages(map_address, mdl);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }

        RtlCopyMemory(map_address, assembly, length);

        if (restore)
        {
            status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READ);
            if (status)
            {
                DbgPrint("[-] Failed second MmProtectMdlSystemAddress with status: 0x%lX\n", status);
                MmUnmapLockedPages(map_address, mdl);
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
                return FALSE;
            }
        }

        MmUnmapLockedPages(map_address, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        return TRUE;
    }

    const BYTE orig_cc[16] = { 0xCC,0xCC,0xCC,0xCC, 0xCC,0xCC, 0xCC,0xCC, 0xCC,0xCC, 0xCC,0xCC, 0xCC,0xCC, 0xCC,0xCC };
    static BOOLEAN patch_codecave_detour(_In_ QWORD address, _In_ QWORD target)
    {
        BYTE assembly[16] =
        {
            0x50,                                                        // push rax
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, TARGET
            0x48, 0x87, 0x04, 0x24,                                      // xchg QWORD PTR[rsp], rax
            0xC3                                                         // retn
        };
        *(QWORD*)(assembly + 3) = target;
        return remap_page((VOID*)address, assembly, 16, TRUE);
    }

    DWORD FindTextSection(char* module, DWORD* size)
    {
        PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

        for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
        {
            PIMAGE_SECTION_HEADER section = &sections[i];
            if (memcmp(section->Name, ".text", 5) == 0)
            {
                *size = section->Misc.VirtualSize;
                return section->VirtualAddress;
            }
        }
        return 0;
    }

    PRTL_PROCESS_MODULES GetModuleList()
    {
        ULONG length = 0;
        ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &length);
        length += (10 * 1024);

        PRTL_PROCESS_MODULES module_list = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, length);
        ZwQuerySystemInformation(SystemModuleInformation, module_list, length, &length);

        if (!module_list)
        {
            //DbgPrintEx(0, 0, "[-] Module List Is Empty\n");
            return 0;
        }
        return module_list;
    }

    VOID Sleep(LONGLONG milliseconds)
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = RELATIVE(MILLISECONDS(milliseconds));
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }

    BOOLEAN WriteToReadOnlyMemory(IN VOID* destination, IN VOID* source, IN ULONG size)
    {
        PMDL mdl = IoAllocateMdl(destination, size, FALSE, FALSE, 0);
        if (!mdl)
            return FALSE;

        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

        PVOID map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
        if (!map_address)
        {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }

        NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(status))
        {
            MmUnmapLockedPages(map_address, mdl);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }

        RtlCopyMemory(map_address, source, size);

        MmUnmapLockedPages(map_address, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return TRUE;
    }

    VOID ToLower(IN CHAR* in, OUT CHAR* out)
    {
        INT i = -1;

        while (in[++i] != '\x00')
        {
            out[i] = (CHAR)tolower(in[i]);
        }
    }

    NTSTATUS OpenPhysicalHandle(PHANDLE handle, PCWSTR diskName)
    {
        OBJECT_ATTRIBUTES objAttr;
        IO_STATUS_BLOCK ioStatusBlock;
        UNICODE_STRING deviceName;
        NTSTATUS status;

        RtlInitUnicodeString(&deviceName, diskName);

        InitializeObjectAttributes(&objAttr, &deviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = ZwCreateFile(
            handle,
            FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
            &objAttr,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);

        return status;
    }
}

VOID* get_module_list()
{
    // We call the function once to get a rough estimate of the size of the structure, then we add a few kb
    ULONG length = 0;
    ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &length);
    length += (10 * 1024);

    VOID* module_list = ExAllocatePool2(POOL_FLAG_PAGED | POOL_COLD_ALLOCATION, length, 55);
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, module_list, length, &length);

    if (status)
    {
        //DbgPrintEx(0, 0, "[-] Failed ZwQuerySystemInformation with 0x%lX\n", status);
        if (module_list) ExFreePool(module_list);
        return 0;
    }

    if (!module_list)
    {
        //DbgPrintEx(0, 0, "[-] Module list is empty\n");
        return 0;
    }

    return module_list;
}

VOID GenerateRandomString(PWCHAR buffer, ULONG length) {
    ULONG seed = (ULONG)KeQueryTimeIncrement();  // Initial seed value

    for (ULONG i = 0; i < length; i++) {
        ULONG randomValue = RtlRandomEx(&seed);
        buffer[i] = 'A' + (randomValue % 26); // Generate a random character from 'A' to 'Z'
    }

    buffer[length] = '\0'; // Null-terminate the string
}

void ReRegisterCallback(PVOID handle, QWORD callback_address)
{
    NTSTATUS status = 0;
    OB_OPERATION_REGISTRATION operations[] = {
        { PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, (POB_PRE_OPERATION_CALLBACK)callback_address, NULL }
    };
    UNICODE_STRING altitudeString;
    RtlInitUnicodeString(&altitudeString, L"505");
    OB_CALLBACK_REGISTRATION callbackRegistration = {
        OB_FLT_REGISTRATION_VERSION,
        1,
        altitudeString,
        NULL,
        operations
    };

    // Register the callback
    status = ObRegisterCallbacks(&callbackRegistration, &handle);
    if (!NT_SUCCESS(status)) {
        //DbgPrintEx(0, 0, "Failed to register callbacks! 0x%X\n", status);
    }
}

OB_PREOP_CALLBACK_STATUS PreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Only interested in handle create operations
    if (OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE)
        return OB_PREOP_SUCCESS;

    // Get the target process
    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE pid = PsGetProcessId(targetProcess);


    if ((DWORD)pid == protected_pid)
    {
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
        OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0;
    }

    return OB_PREOP_SUCCESS;
}