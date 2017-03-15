#include <windows.h>
#include "shell.h"
#include "error.h"
#include "pe_utilities.h"
#include "config.h"


/*
	Description:	安置shell区块
*/
int ImployShell(void* _pImageBase, void** _ppShellSection)
{
	const PIMAGE_NT_HEADERS pNTHeader = getNTHeader(_pImageBase);
	const PIMAGE_SECTION_HEADER pLastSecHeader = getLastSecHeader(_pImageBase);
	unsigned long shellrawsize = (unsigned long)(&Label_Shell_End) - (unsigned long)(&Label_Shell_Start);

	CreateNewSection(_pImageBase, shellrawsize, _ppShellSection);

	// 把shell的数据写入shell映像中
	memcpy(*_ppShellSection, (&Label_Shell_Start), shellrawsize);


	/*  TODO : 修复SHELL的自建输入表  */

	/*  TODO : 填写shell相关数据字段  */
	PInduction_Data pInductionData = (PInduction_Data)(&Label_Induction_Data_Start);
	pInductionData->LuanchBase = pLastSecHeader->VirtualAddress + (DWORD)(&Label_Luanch_Start) - (DWORD)(&Label_Shell_Start);
	pInductionData->nLuanchPackSize = (DWORD)(&Label_Luanch_End) - (DWORD)(&Label_Shell_Start);
	PLuanch_Data pLuanchData = (PLuanch_Data)(&Lable_Luanch_Data_Start);
	pLuanchData->OEP = pNTHeader->OptionalHeader.AddressOfEntryPoint;
	pLuanchData->IsMutateImpTable = ISMUTATEIMPORT ? 1 : 0;
	pLuanchData->OriginalImpTableAddr = 0;
	pLuanchData->IsDLL = 0;
	pLuanchData->OriginalRelocAddr = 0;


	/*  TODO : 修复PE头,使目标文件以shell为入口点  */
	/*  AddressOfEntryPoint, BaseOfCode  , DataDirectory[IMPORT,IAT]*/
	pNTHeader->OptionalHeader.AddressOfEntryPoint = pLastSecHeader->VirtualAddress;
	pNTHeader->OptionalHeader.BaseOfCode = pLastSecHeader->VirtualAddress;
	pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pLastSecHeader->VirtualAddress + (DWORD)(&Label_Mutate_Import_Start) - (DWORD)(&Label_Shell_Start);
	pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (DWORD)(&Label_Mutate_Import_End) - (DWORD)(&Label_Mutate_Import_Start);
	pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;

	return	ERR_SUCCESS;
}