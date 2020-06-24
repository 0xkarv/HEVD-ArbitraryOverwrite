#pragma once
#pragma once
#include<windows.h>

//GDI BitMap Palette

typedef struct _HEAD
{
	HANDLE h;
	DWORD  cLockObj;
} HEAD, *PHEAD;

typedef struct _THROBJHEAD
{
	HEAD h;
	PVOID pti;
} THROBJHEAD, *PTHROBJHEAD;
//
typedef struct _THRDESKHEAD
{
	THROBJHEAD h;
	PVOID    rpdesk;
	PVOID       pSelf; 
} THRDESKHEAD, *PTHRDESKHEAD;

typedef struct _G_PALETTE
{
	HPALETTE _hpalette;
	DWORD64 _kobj_palette;
	DWORD flag;
} GPALETTE, *PGPALETTE;

typedef struct _hBmp
{
	HBITMAP hBmp;
	DWORD64 kAddr;
	PUCHAR pvScan0;
}HBMP,*PHBMP;
