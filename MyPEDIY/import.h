#ifndef __IMPORT_H__
#define __IMPORT_H__

#include <Windows.h>
#include <vector>

/*
	FirstThunk|DLLName[32]|nFunc|FuncName[32]...
*/
struct MutateImportThunkNode
{
	union 
	{
		DWORD	Ordinal;
		char	FuncName[32];
	};
};
struct MutateImportNode 
{
	DWORD								FirstThunk;
	char								DLLName[32];
	DWORD								nFunc;
	std::vector<MutateImportThunkNode>	vThunks;
};
typedef MutateImportNode UNALIGNED *PMutateImportNode;


struct MutateImportInfo
{
	void *pMutateImport;
	unsigned long nMutateImport;
};
typedef MutateImportInfo *PMutateImportInfo;


/*
	Description:	�������촦��
*/
int MutateImport(void *_pImageBase, PMutateImportInfo _pMutateImportInfo);


/*
	Description:	����������������Ҫ�Ĵ�С
*/
unsigned long CalcMutateImpSize(std::vector<MutateImportNode> &_rvMuateImport);


#endif // __IMPORT_H__
