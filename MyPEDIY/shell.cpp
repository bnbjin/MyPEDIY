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
	unsigned long shellrawsize = (unsigned long)(&Label_Shell_End) - (unsigned long)(&Label_Shell_Start);

	CreateNewSection(_pImageBase, shellrawsize, _ppShellSection);

	// 把shell的数据写入shell映像中
	memcpy(*_ppShellSection, (&Label_Shell_Start), shellrawsize);

	const PIMAGE_NT_HEADERS pNTHeader = getNTHeader(_pImageBase);
	const PIMAGE_SECTION_HEADER pLastSecHeader = getLastSecHeader(_pImageBase);
	
	
	/*  TODO : 修复SHELL的自建输入表  */
	/* Import Descriptor: FirstThunk, OriginalFirstThunk, Name */
	/* Thunks */
	PInduction_Import pInductionImp = (PInduction_Import)((unsigned long)(*_ppShellSection) + (unsigned long)(&Label_Induction_Import_Start) - (unsigned long)(&Label_Shell_Start));
	pInductionImp->ImpD[0].FirstThunk += pLastSecHeader->VirtualAddress;
	pInductionImp->ImpD[0].OriginalFirstThunk += pLastSecHeader->VirtualAddress;
	pInductionImp->ImpD[0].Name += pLastSecHeader->VirtualAddress;
	pInductionImp->Thunk[0].u1.AddressOfData += pLastSecHeader->VirtualAddress;
	pInductionImp->Thunk[1].u1.AddressOfData += pLastSecHeader->VirtualAddress;
	pInductionImp->Thunk[2].u1.AddressOfData += pLastSecHeader->VirtualAddress;
	

	/*  TODO : 填写shell相关数据字段  */
	PInduction_Data pInductionData = (PInduction_Data)((unsigned long)(*_ppShellSection) + (unsigned long)(&Label_Induction_Data_Start) - (unsigned long)(&Label_Shell_Start));
	pInductionData->LuanchBase = (DWORD)(&Label_Luanch_Start) - (DWORD)(&Label_Shell_Start);
	pInductionData->nLuanchOriginalSize = (DWORD)(&Label_Luanch_End) - (DWORD)(&Label_Luanch_Start);
	PLuanch_Data pLuanchData = (PLuanch_Data)((unsigned long)(*_ppShellSection) + (unsigned long)(&Lable_Luanch_Data_Start) - (unsigned long)(&Label_Shell_Start));
	pLuanchData->OEP = pNTHeader->OptionalHeader.AddressOfEntryPoint;
	pLuanchData->IsMutateImpTable = ISMUTATEIMPORT ? 1 : 0;
	pLuanchData->OriginalImpTableAddr = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	pLuanchData->IsDLL = 0;
	pLuanchData->OriginalRelocAddr = 0;


	/*  TODO : 修复PE头,使目标文件以shell为入口点  */
	/*  AddressOfEntryPoint, BaseOfCode  , DataDirectory[IMPORT,IAT]*/
	pNTHeader->OptionalHeader.AddressOfEntryPoint = pLastSecHeader->VirtualAddress;
	pNTHeader->OptionalHeader.BaseOfCode = pLastSecHeader->VirtualAddress;
	pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pLastSecHeader->VirtualAddress + (DWORD)(&Label_Induction_Import_Start) - (DWORD)(&Label_Shell_Start);
	pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (DWORD)(&Label_Induction_Import_End) - (DWORD)(&Label_Induction_Import_Start);
	pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = pLastSecHeader->VirtualAddress + (DWORD)(&Label_Induction_Import_End) - (DWORD)(&Label_Shell_Start);
	pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 4 * sizeof(DWORD);

	return	ERR_SUCCESS;
}