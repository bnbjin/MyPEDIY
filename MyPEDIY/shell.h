#ifndef __SHELL_H__
#define __SHELL_H__

#include <windows.h>


/*  shell中的变量  */
extern "C"	DWORD	Label_Shell_Start;
extern "C"	DWORD	Label_Shell_End;
extern "C"	DWORD	Label_Induction_Start;
extern "C"  DWORD   Label_Induction_End;
extern "C"	DWORD	Label_Induction_Data_Start;
extern "C"	DWORD	Label_Induction_Data_End;
extern "C"  DWORD	Label_Mutate_Import_Start;
extern "C"	DWORD	Label_Mutate_Import_End;
extern "C"	DWORD	Label_Luanch_Start;
extern "C"	DWORD	Label_Luanch_End;
extern "C"	DWORD	Lable_Luanch_Data_Start;
extern "C"	DWORD	Lable_Luanch_Data_End;

#pragma pack(push)
#pragma pack(1)
struct Induction_Data 
{
	DWORD	nShellStep;
	DWORD	LuanchBase;
	DWORD   LuanchAllocBase;
	DWORD   ImageBase;
	DWORD   nLuanchPackSize;
	BYTE	szVirtualAlloc[13];
	DWORD	VirtualAllocAddr;
	BYTE	TlsTable[18];
};

struct Luanch_Data
{
	DWORD	OEP;
	DWORD	IsMutateImpTable;
	DWORD	OriginalImpTableAddr;
	DWORD	IsDLL;
	DWORD	OriginalRelocAddr;
};
#pragma pack(pop)

typedef Induction_Data* UNALIGNED PInduction_Data;
typedef Luanch_Data* UNALIGNED PLuanch_Data;

/*
	Description:	安置shell区块,_pShellSection需要调用者delete
*/
int ImployShell(void* _pImageBase, void **_ppShellSection);


#endif // __SEHLL_H__
