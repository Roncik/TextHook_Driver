

#include "memory_utils.hpp"



#define SystemModuleInformation 0x0B
extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

typedef LDR_DATA_TABLE_ENTRY*(*MiLookupDataTableEntry_fn)(IN VOID* Address, IN BOOLEAN);
MiLookupDataTableEntry_fn MiLookupDataTableEntry;

QWORD g_callback_address = 0, g_thread_address = 0;


//VOID create_process_callback(UNICODE_STRING* image_name, HANDLE process_id, IMAGE_INFO* image_info)
//{
//	if ((process_id == NULL || process_id == (HANDLE)4) && image_name != NULL && wcsstr(image_name->Buffer, L"BEDaisy.sys")) {
//		// hook import
//		be_module = (QWORD)Utils::GetSystemModuleBase(L"BEDaisy.sys");
//		ExAllocatePool_Report_Counter = 1000;
//		openfile_battleye_counter = 0;
//		Init_Completed = false;
//		Utils::IATHook((PVOID)be_module, "MmGetSystemRoutineAddress", &Hook_MmGetSystemRoutineAddress);
//	}
//	else if (image_name != NULL && wcsstr(image_name->Buffer, L"EasyAntiCheat") && wcsstr(image_name->Buffer, L".sys"))
//	{
//		HANDLE pid = process_id;
//		PEPROCESS process;
//		PVOID base = Utils::GetSystemModuleBase(L"EasyAntiCheat.sys");
//		if (!base)
//			base = Utils::GetSystemModuleBase(L"EasyAntiCheat_EOS.sys");
//		if (base)
//		{
//			Utils::WriteProtectOff();
//			memset(base, 0, 0x1000);
//			Utils::WriteProtectOn();
//		}
//	}
//	//DbgPrintEx(0, 0, "Driver Loaded: %S", (WCHAR*)image_name->Buffer);
//}

VOID main_thread()
{
	//DbgPrintEx(0, 0, "[+] Inside main thread\n");
	PDEVICE_OBJECT pDeviceObject;
	UNICODE_STRING dev, dos;

	if (!restore_codecave_detour(g_thread_address))
	{
		//DbgPrintEx(0, 0, "[-] Failed restoring thread code cave!\n");
}
	else
	{
		//DbgPrintEx(0, 0, "[+] Restored thread code cave");
	}

	

	//NTSTATUS status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)g_callback_address);
	NTSTATUS status = 0;
	OB_OPERATION_REGISTRATION operations[] = {
		{ PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, (POB_PRE_OPERATION_CALLBACK)g_callback_address, NULL }
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
	status = ObRegisterCallbacks(&callbackRegistration, &g_CallbackHandle);
	if (!NT_SUCCESS(status)) {
		//DbgPrintEx(0, 0, "Failed to register callbacks! 0x%X\n", status);
	}

}

BOOLEAN apply_codecaves()
{
	VOID* module_list = get_module_list();
	if (!module_list) return FALSE;
	RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)module_list;
	
	/*
		We need to find 2 16 byte codecaves, preferably in the same module:
		g_callback_address will be the detour to the CreateProcess callback
		g_thread_address will be the detour for our main thread
	*/
	for (ULONG i = 1; i < modules->NumberOfModules; ++i)
	{
		RTL_PROCESS_MODULE_INFORMATION* module = &modules->Modules[i];

		CHAR driver_name[0x0100] = { 0 };
		to_lower(module->FullPathName, driver_name);
		/*if (!strstr(driver_name, ".sys") || is_pg_protected(driver_name)) 
			continue;*/

		if (!strstr(driver_name, "iorate.sys"))
			continue;

		QWORD Address = find_pattern_nt("50 48 B8 ? ? ? ? ? ? ? ? 48 87 04 24 C3", (QWORD)module->ImageBase, module->ImageSize);
		if (Address)
		{
			//DbgPrintEx(0, 0, "Already mapped\n");

			if (!patch_codecave_detour(Address, (QWORD)&PreOperationCallback))
			{
				//DbgPrintEx(0, 0, "[-] Failed patching in create_process_callback redirection code cave!\n");
				return TRUE;
			}

			return TRUE;
		}

		g_callback_address = find_codecave(module->ImageBase, 16, 0);
		if (!g_callback_address) continue;

		g_thread_address = find_codecave(module->ImageBase, 16, g_callback_address + 16);
		_be_pre_ob_callback_cave = g_thread_address;
		if (!g_thread_address)
		{
			g_callback_address = 0;
			continue;
		}

		LDR_DATA_TABLE_ENTRY* ldr = MiLookupDataTableEntry((VOID*)g_callback_address, FALSE);
		if (!ldr)
		{
			g_callback_address = g_thread_address = 0;
			continue;
		}
		// Setting the 0x20 data table entry flag makes MmVerifyCallbackFunction pass
		ldr->Flags |= 0x20;
		//DbgPrintEx(0, 0, "[+] Found places for both code caves in module %s\n", driver_name + module->OffsetToFileName);

		break;
	}

	ExFreePool(module_list);

	/*
		Instead of just stopping we could loosen our restrictions and search for 2 code caves in separate modules
		But in practice, 16 byte code caves are quite common, so this shouldn't really happen
	*/
	if (!g_callback_address || !g_thread_address)
	{
		//DbgPrintEx(0, 0, "[-] Failed to find all required code caves in any driver module!\n");
		return FALSE;
	}

	if (!patch_codecave_detour(g_callback_address, (QWORD)&PreOperationCallback))
	{
		//DbgPrintEx(0, 0, "[-] Failed patching in create_process_callback redirection code cave!\n");
		return FALSE;
	}

	if (!patch_codecave_detour(g_thread_address, (QWORD)&main_thread))
	{
		//DbgPrintEx(0, 0, "[-] Failed patching in main_thread redirection code cave!\n");
		return FALSE;
	}

	//DbgPrintEx(0, 0, "[+] Patched in both code caves succesfully\n");

	HANDLE thread;
	NTSTATUS status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, 0, 0, 0, (KSTART_ROUTINE*)g_thread_address, 0);
	if (status)
	{
		//DbgPrintEx(0, 0, "[-] PsCreateSystemThread failed, status = 0x%08X\n", status);
	}
	else
	{
		//DbgPrintEx(0, 0, "[+] Created a system thread in target space\n");
	}

	return TRUE;
}

NTSTATUS ReadRegistryDword(PCWSTR RegistryPath, PCWSTR ValueName, DWORD* Value) 
{
	UNICODE_STRING unicodeRegistryPath;
	UNICODE_STRING unicodeValueName;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE registryKeyHandle;
	NTSTATUS status;
	ULONG resultLength;
	UCHAR keyValueInformationBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(DWORD)];
	PKEY_VALUE_PARTIAL_INFORMATION keyValueInformation = (PKEY_VALUE_PARTIAL_INFORMATION)keyValueInformationBuffer;

	// Initialize the UNICODE_STRINGs
	RtlInitUnicodeString(&unicodeRegistryPath, RegistryPath);
	RtlInitUnicodeString(&unicodeValueName, ValueName);

	// Initialize the OBJECT_ATTRIBUTES for the registry key
	InitializeObjectAttributes(
		&objectAttributes,
		&unicodeRegistryPath,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	// Open the registry key
	status = ZwOpenKey(&registryKeyHandle, KEY_READ, &objectAttributes);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// Query the value
	status = ZwQueryValueKey(
		registryKeyHandle,
		&unicodeValueName,
		KeyValuePartialInformation,
		keyValueInformation,
		sizeof(keyValueInformationBuffer),
		&resultLength
	);

	if (NT_SUCCESS(status) && keyValueInformation->Type == REG_DWORD) {
		// Copy the DWORD value to the output parameter
		*Value = *(DWORD*)keyValueInformation->Data;
	}

	// Close the registry key handle
	ZwClose(registryKeyHandle);

	return status;
}

//NTSTATUS OLDDriverEntry(DRIVER_OBJECT* driver_object, UNICODE_STRING* registry_path)
//{
//	UNREFERENCED_PARAMETER(driver_object);
//	UNREFERENCED_PARAMETER(registry_path);
//	DbgPrintEx(0, 0, "Start\n");
//	void* module_list = get_module_list();
//	if (!module_list) return STATUS_UNSUCCESSFUL;
//	RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)module_list;
//
//	// First module is always ntoskrnl.exe
//	RTL_PROCESS_MODULE_INFORMATION* module = &modules->Modules[0];
//
//	QWORD address = find_pattern_nt("48 8B C4 48 89 58 08 48 89 70 18 57 48 83 EC 20 33 F6", (QWORD)module->ImageBase, module->ImageSize);
//	if (!address) 
//	{
//		address = find_pattern_nt("48 89 5C 24 08 48 89 6C 24 18 48 89 74 24 20 57 48 83 EC 20 33 ED", (QWORD)module->ImageBase, module->ImageSize);
//		if (!address)
//		{
//			DbgPrintEx(0, 0, "[-] Could not find MiLookupDataTableEntry\n");
//			return STATUS_UNSUCCESSFUL;
//		}
//	}
//	DbgPrintEx(0, 0, "[+] Found MiLookupDataTableEntry at 0x%p\n", (VOID*)address);
//	MiLookupDataTableEntry = (MiLookupDataTableEntry_fn)address;
//
//	ExFreePool(module_list);
//	if (!apply_codecaves()) 
//		DbgPrintEx(0,0,"[-] Failed applying code caves\n");
//
//	return STATUS_UNSUCCESSFUL;
//}