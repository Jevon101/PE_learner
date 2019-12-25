#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define POINTER_TYPE DWORD
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))

PBYTE GetRsrc(char *FileName);

bool LoadPE(PBYTE lpBuf);
bool CheckIsAviliablePE(PBYTE pBuf);
DWORD AlignSection(DWORD dwSize, DWORD Align);
DWORD GetMyProcAddress(PBYTE pAllocPE, TCHAR* szFuncName);
