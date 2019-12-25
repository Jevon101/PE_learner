
#include <stdio.h>
#include <windows.h>

IMAGE_DOS_HEADER myDosHeader;
IMAGE_NT_HEADERS myNtHeader;
IMAGE_FILE_HEADER myFileHeader;
IMAGE_OPTIONAL_HEADER myOptionHeader;
IMAGE_SECTION_HEADER* pmySectionHeader;

long e_lfanew;
int SectionCount;
int Signature;

int main(int argc, char* argv[])
{
	//打开PE文件
	FILE* fp = fopen("D:\\tiny.exe", "rb");
	if (fp == NULL)
	{
		printf(" File can not open!\n");
		exit(0);
	}

	//DOS头
	printf("================IMAGE_DOS_HEADER================\n");
	fread(&myDosHeader, sizeof(IMAGE_DOS_HEADER), 1, fp);
	printf("WORD  e_magic:				%04X\n", myDosHeader.e_magic);
	printf("DWORD e_lfanew:				%08X\n\n\n", myDosHeader.e_lfanew);
	e_lfanew = myDosHeader.e_lfanew;


	//NT头
	printf("================IMAGE_NT_HEADER=================\n");
	fseek(fp, e_lfanew, SEEK_SET);
	fread(&myNtHeader, sizeof(IMAGE_NT_HEADERS), 1, fp);
	Signature = myNtHeader.Signature;
	if (Signature != 0x4550)
	{
		printf(" This is not a PE file!\n");
		exit(0);
	} 
	printf("DWORD Signature:			%08x\n\n\n", Signature);
	

	//FILE头
	printf("================IMAGE_FILE_HEADER================\n");
	fseek(fp, (e_lfanew + sizeof(DWORD)), SEEK_SET);
	fread(&myFileHeader, sizeof(IMAGE_FILE_HEADER), 1, fp);
	printf("WORD Machine:				%04X\n", myFileHeader.Machine);
	printf("WORD NumberOfSections:			%04X\n", myFileHeader.NumberOfSections);
	printf("DWORD TimeDateStamp:			%08X\n", myFileHeader.TimeDateStamp);
	printf("DWORD PointerToSymbolTable:		%08X\n", myFileHeader.PointerToSymbolTable);
	printf("DWORD NumberOfSymbols:			%08X\n", myFileHeader.NumberOfSymbols);
	printf("WORD SizeOfOptionalHeader:		%04X\n", myFileHeader.SizeOfOptionalHeader);
	printf("WORD Characteristics:			%04X\n\n\n", myFileHeader.Characteristics);
	SectionCount = myFileHeader.NumberOfSections;


	//OPTIONAL头
	printf("================IMAGE_OPTIONAL_HEADER=============\n");
	fseek(fp, (e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)), SEEK_SET);
	fread(&myOptionHeader, sizeof(IMAGE_OPTIONAL_HEADER), 1, fp);
	printf("WORD Magic:				%04X\n", myOptionHeader.Magic);
	printf("BYTE MajorLinkerVersion:		%02X\n", myOptionHeader.MajorLinkerVersion);
	printf("BYTE MinorLinkerVersion:		%02X\n", myOptionHeader.MinorLinkerVersion);
	printf("DWORD SizeOfCode:			%08X\n", myOptionHeader.SizeOfCode);
	printf("DWORD SizeOfInitializedData:		%08X\n", myOptionHeader.SizeOfInitializedData);
	printf("DWORD SizeOfUninitializedData:		%08X\n", myOptionHeader.SizeOfUninitializedData);
	printf("DWORD AddressOfEntryPoint:		%08X\n", myOptionHeader.AddressOfEntryPoint);
	printf("DWORD BaseOfCode:			%08X\n", myOptionHeader.BaseOfCode);
	printf("DWORD BaseOfData:			%08X\n", myOptionHeader.BaseOfData);
	printf("DWORD ImageBase:			%08X\n", myOptionHeader.ImageBase);
	printf("DWORD SectionAlignment:			%08X\n", myOptionHeader.SectionAlignment);
	printf("DWORD FileAlignment:			%08X\n", myOptionHeader.FileAlignment);
	printf("WORD MajorOperatingSystemVersion:	%04X\n", myOptionHeader.MajorOperatingSystemVersion);
	printf("WORD MinorOperatingSystemVersion:	%04X\n", myOptionHeader.MinorOperatingSystemVersion);
	printf("WORD MajorImageVersion:			%04X\n", myOptionHeader.MajorImageVersion);
	printf("WORD MinorImageVersion:			%04X\n", myOptionHeader.MinorImageVersion);
	printf("WORD MajorSubsystemVersion:		%04X\n", myOptionHeader.MajorSubsystemVersion);
	printf("WORD MinorSubsystemVersion:		%04X\n", myOptionHeader.MinorSubsystemVersion);
	printf("DWORD Win32VersionValue:		%08X\n", myOptionHeader.Win32VersionValue);
	printf("DWORD SizeOfImage:			%08X\n", myOptionHeader.SizeOfImage);
	printf("DWORD SizeOfHeaders:			%08X\n", myOptionHeader.SizeOfHeaders);
	printf("DWORD CheckSum:				%08X\n", myOptionHeader.CheckSum);
	printf("WORD Subsystem:				%04X\n", myOptionHeader.Subsystem);
	printf("WORD DllCharacteristics:		%04X\n", myOptionHeader.DllCharacteristics);
	printf("DWORD SizeOfStackReserve:		%08X\n", myOptionHeader.SizeOfStackReserve);
	printf("DWORD SizeOfStackCommit:		%08X\n", myOptionHeader.SizeOfStackCommit);
	printf("DWORD SizeOfHeapReserve:		%08X\n", myOptionHeader.SizeOfHeapReserve);
	printf("DWORD SizeOfHeapCommit:			%08X\n", myOptionHeader.SizeOfHeapCommit);
	printf("DWORD LoaderFlags:			%08X\n", myOptionHeader.LoaderFlags);
	printf("DWORD NumberOfRvaAndSizes:		%08X\n\n\n", myOptionHeader.NumberOfRvaAndSizes);


	//Directories
	printf("=================IMAGE_DATA_DIRECTORY==============\n\n");
	const char* dir[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {"EXPORT Directory","IMPORT Directory","RESOURCE Directory"
														 "EXCEPTION Directory","SECURITY Directory","BASERELOC Directory"
														 "DEBUG Directory","COPYRIGHT Directory","GLOBALPTR Directory"
														 "TLS Directory","LOAD_CONFIG Directory","BOUND_IMPORT Directory"
														 "IAT Directory",""};
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		printf("=================%s==============\n", dir[i]);
		printf("DWORD VirtualAddress:		%08X\n", myOptionHeader.DataDirectory[i].VirtualAddress);
		printf("DWORD Size:			%08X\n", myOptionHeader.DataDirectory[i].Size);
	}
	printf("\n\n");
	

	//节表
	printf("================IMAGE_SECTION_DIRECTORY=============\n");
	pmySectionHeader = (IMAGE_SECTION_HEADER*)calloc(SectionCount, sizeof(IMAGE_SECTION_HEADER));
	fseek(fp, (e_lfanew + sizeof(IMAGE_NT_HEADERS)), SEEK_SET);
	fread(pmySectionHeader, sizeof(IMAGE_SECTION_HEADER), SectionCount, fp);
	
	for (int i = 0; i < SectionCount; i++, pmySectionHeader++)
	{
		printf("BYTE Name:				%s\n", pmySectionHeader->Name);
		printf("DWORD PhysicalAddress			%08X\n", pmySectionHeader->Misc.PhysicalAddress);
		printf("DWORD VirtualSize			%08X\n", pmySectionHeader->Misc.VirtualSize);
		printf("DWORD VirtualAddress			%08X\n", pmySectionHeader->VirtualAddress);
		printf("DWORD SizeOfRawData			%08X\n", pmySectionHeader->SizeOfRawData);
		printf("DWORD PointerToRawData			%08X\n", pmySectionHeader->PointerToRawData);
		printf("DWORD PointerToRelocations		%08X\n", pmySectionHeader->PointerToRelocations);
		printf("DWORD PointerToLinenumbers		%08X\n", pmySectionHeader->PointerToLinenumbers);
		printf("WORD NumberOfRelocations		%04X\n", pmySectionHeader->NumberOfRelocations);
		printf("WORD NumberOfLinenumbers		%04X\n", pmySectionHeader->NumberOfLinenumbers);
		printf("DWORD Characteristics			%08X\n\n", pmySectionHeader->Characteristics);

	}

	if (pmySectionHeader != NULL)
	{
		pmySectionHeader = NULL;
	}

	fclose(fp);
	getchar();
	return 0;
}
