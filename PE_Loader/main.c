#include "myPELoader.h"

typedef void (*PTestFunc)();

void main(int argc,char *argv[])
{
	char address[] = "E:\\#RE#\\PE_Loader\\LoadMemDll-master\\DLL_BIN.dll";
	PBYTE pBuf = GetRsrc(address);

	if (!pBuf)
	{
		OutputDebugStringA("Get Rsrc err");
		exit(0);
	}

	if (!LoadPE(pBuf)) 
	{
		OutputDebugStringA("LoadPE err");
		exit(0);
	}


}
