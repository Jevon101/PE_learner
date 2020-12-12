#include "myPELoader.h"

typedef void (*PTestFunc)();

int main(int argc,char *argv[])
{
	char address[] = "Your PE Address";
	PBYTE pBuf = GetRsrc(address);

	if (!pBuf)
	{
		printf("Get Rsrc err");
		return -1;
	}

	if (!LoadPE(pBuf)) 
	{
		printf("LoadPE err");
		return -1;
	}

	return 0;
}
