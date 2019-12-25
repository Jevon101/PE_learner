#include "myPELoader.h"


typedef   BOOL(__stdcall* ProcDLLMain)(HINSTANCE, DWORD, LPVOID);
typedef   BOOL(__cdecl* ProcMain)();

bool LoadPE(PBYTE lpBuf) 
{
	LPBYTE pAllocPE = NULL;
	if (!CheckIsAviliablePE(lpBuf))
	{
		return false;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpBuf + pDosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);
	DWORD dwSecAlign = pNtHeader->OptionalHeader.SectionAlignment;
	DWORD dwFileAlogn = pNtHeader->OptionalHeader.FileAlignment;

	pAllocPE = (LPBYTE)VirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pAllocPE == NULL)
	{
		return false;

	}
	memset(pAllocPE, 0, pNtHeader->OptionalHeader.SizeOfImage);//初始化
	
	//Copy Header
	DWORD dwHeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
	memmove(pAllocPE, lpBuf, dwHeaderSize);

	//循环加载每一个节区
	while (pSecHeader->VirtualAddress || pSecHeader->SizeOfRawData)
	{
		if (pNtHeader->OptionalHeader.FileAlignment > pNtHeader->OptionalHeader.SectionAlignment) 
		{
			OutputDebugStringA("ERROR");
			return false;
		}
		DWORD dwSecImageSize = AlignSection(pSecHeader->Misc.VirtualSize, dwSecAlign);
		DWORD dwSecFileSize = pSecHeader->SizeOfRawData;
		DWORD dwRealSize = dwSecImageSize > dwSecFileSize ? dwSecFileSize : dwSecImageSize;//choose min 多余的都是0
		memmove(pSecHeader->VirtualAddress + pAllocPE, pSecHeader->PointerToRawData + lpBuf, dwRealSize);

		//next section
		pSecHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pSecHeader + sizeof(IMAGE_SECTION_HEADER));
	}

	fclose((FILE*)lpBuf);

	//重定位表的处理
	if (pNtHeader->OptionalHeader.ImageBase - (DWORD)pAllocPE == 0) 
	{
		;
	}else 
	{
		DWORD dwOriImage = pNtHeader->OptionalHeader.ImageBase;
		PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pAllocPE);
		int SizeOfRelocDirectory = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		int NumberOfReclocAddress;
		int SizeOfRelocBlock;
		DWORD BaseRva = pBaseReloc->VirtualAddress;
		DWORD Different = (DWORD)pAllocPE - pNtHeader->OptionalHeader.ImageBase;//地址差

		while (SizeOfRelocDirectory)
		{
			SizeOfRelocBlock = pBaseReloc->SizeOfBlock;
			if (SizeOfRelocBlock == 0) 
			{
				break;
			}
			NumberOfReclocAddress = (SizeOfRelocBlock - 8) / 2;//一页内的数目
			BaseRva = pBaseReloc->VirtualAddress;
			WORD* pTypeOffset = (WORD*)((BYTE*)pBaseReloc + 8);
			
			//一页内重定位
			for (int nIndex = 0; nIndex < NumberOfReclocAddress; nIndex++)
			{
				int type = pTypeOffset[nIndex] >> 12;//右移动12位
				DWORD offset = pTypeOffset[nIndex] & 0x0FFF;//取后12位
				switch (type)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					// 0 nothing
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*(PDWORD)(pAllocPE + offset + BaseRva) += Different;//修改偏移
					break;// 3 
				default:
					break;
				}

			}
			//翻页
			SizeOfRelocDirectory -= SizeOfRelocBlock;
			pBaseReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pBaseReloc + SizeOfRelocBlock);
		}
	}

	//导入表的处理
	if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) 
	{
		;
	}else 
	{
		PIMAGE_IMPORT_DESCRIPTOR pIID;
		pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + pAllocPE);

		while (pIID->Name != NULL)
		{
			char szDllName[0x40];
			strcpy(szDllName, (char*)(pIID->Name + pAllocPE));
			
			HMODULE hLibrary = LoadLibraryA(szDllName);
			if (!hLibrary)
			{
				char szInfo[0x40];
				sprintf(szInfo, "未找到DLL%s", szDllName);
				MessageBoxA(0, szInfo, "Error", 0);
				return false;
			}

			PIMAGE_THUNK_DATA32 pIAT_Table = (PIMAGE_THUNK_DATA32)(pIID->FirstThunk +pAllocPE);
			PIMAGE_THUNK_DATA32 pINT_Table = (PIMAGE_THUNK_DATA32)(pIID->OriginalFirstThunk + pAllocPE);

			//处理DLL内函数
			while (true) 
			{
				PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(pINT_Table->u1.AddressOfData + pAllocPE);
				if (pINT_Table->u1.AddressOfData == NULL)
				{
					break;
				}
				if (pINT_Table->u1.AddressOfData & IMAGE_ORDINAL_FLAG32)		//测试这个位的掩码为0x80000000(PE32)是通过序数导入的。否则是通过名称导入的
				{
					pIAT_Table->u1.AddressOfData = (DWORD)GetProcAddress(hLibrary, (LPCSTR)((WORD)pINT_Table->u1.Ordinal)); 
				}
				else
				{
					pIAT_Table->u1.AddressOfData = (DWORD)GetProcAddress(hLibrary, (LPCSTR)pImportName->Name);
				}
				pINT_Table++;
				pIAT_Table++;

			}
			pIID++;
		}		
	}

	//启动Main

	bool bStatus = false;
	if (pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) 
	{
		ProcDLLMain pMain = (ProcDLLMain)(pNtHeader->OptionalHeader.AddressOfEntryPoint + pAllocPE);
		bStatus = pMain((HINSTANCE)pAllocPE, DLL_PROCESS_ATTACH, 0);
		if (!bStatus)
		{
			pMain((HINSTANCE)pAllocPE, DLL_PROCESS_DETACH, 0);
			VirtualFree(pAllocPE, 0, MEM_RELEASE);
			return false;
		}
	}else 
	{
		ProcMain pMain = (ProcMain)(pNtHeader->OptionalHeader.AddressOfEntryPoint + pAllocPE);
		__asm
		{
			mov eax, pMain
			jmp eax
		}

	}
	

	
	
	// 跳转到入口点处执行
	/*__asm
	{
		mov eax, ExeEntry
		jmp eax
	}*/
	return true;

}


//Open PE
PBYTE GetRsrc(char *FileName) 
{
	FILE* fp = fopen(FileName, "rb+");
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);

	fseek(fp, 0, SEEK_SET);
	char* pBuf = NULL;

	pBuf = (char*)malloc(size);
	fread(pBuf, size, 1, fp);

	return (PBYTE)pBuf;
}


//Check File
bool CheckIsAviliablePE(PBYTE pBuf) 
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS32 pNtHeader = (PIMAGE_NT_HEADERS32)(pDosHeader->e_lfanew + pBuf);
	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE) 
	{
		if (pNtHeader->Signature == IMAGE_NT_SIGNATURE) 
		{
			return true;
		}
	}
	return false;
}


//内存对齐
DWORD AlignSection(DWORD dwSize, DWORD Align)
{
	return ((dwSize + Align - 1) / Align * Align);
}


//GetMyProcAddress
DWORD GetMyProcAddress(PBYTE pAllocPE,TCHAR* szFuncName) 
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pAllocPE;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pAllocPE + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + pAllocPE);
	PDWORD pAddressOfNamesTable = (PDWORD)(pExportDirectory->AddressOfNames + pAllocPE);
	PWORD pAddressOfOridinalTable = (PWORD)(pExportDirectory->AddressOfNameOrdinals + pAllocPE);

	if (IsBadReadPtr(szFuncName, 1))			// 如果调用进程有权限访问该内存，返回0
	{
		WORD Base = pExportDirectory->Base;
		WORD index = (WORD)szFuncName - Base;
		if (index >= pExportDirectory->NumberOfFunctions)
			return 0;
		return *(PWORD)((PDWORD)(pExportDirectory->AddressOfFunctions + pAllocPE) + index) + (DWORD)pAllocPE;
	}
	else
	{
		for (int i = 0; i < pExportDirectory->NumberOfNames; i++)
		{
			if (strcmp((char*)szFuncName, (char*)(*(pAddressOfNamesTable + i) + pAllocPE)) == 0)
			{
				WORD index = *(pAddressOfOridinalTable + i);
				return *(PWORD)((PDWORD)(pExportDirectory->AddressOfFunctions + pAllocPE) + index) + (DWORD)pAllocPE;
			}
		}
	}
	return 0;


}
