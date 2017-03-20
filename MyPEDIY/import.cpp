#include "import.h"
#include "error.h"
#include "pe_utilities.h"


/*
FirstThunk|DLLName[32]|nFunc|FuncName[32]...
*/
/*
	Description:	输入表变异处理
*/
int MutateImport(void *_pImageBase, PMutateImportInfo _pMutateImportInfo)
{
	PIMAGE_NT_HEADERS pNTHeader = getNTHeader(_pImageBase);
	PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)RVAToPtr(_pImageBase, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_THUNK_DATA pThunk;
	std::vector<MutateImportNode> vMuateImport;
	MutateImportNode tmpImportNode;
	MutateImportThunkNode tmpImpThunkNode;

	/*  把原输入表关键信息读入  */
	while (0 != pIID->FirstThunk)
	{
		memset(&tmpImportNode, 0, sizeof(MutateImportNode));

		strcpy_s(tmpImportNode.DLLName, (char*)RVAToPtr(_pImageBase, pIID->Name));
		tmpImportNode.FirstThunk = pIID->FirstThunk;

		pThunk = (PIMAGE_THUNK_DATA)RVAToPtr(_pImageBase, pIID->FirstThunk);
		while (pThunk->u1.AddressOfData)
		{
			memset(&tmpImpThunkNode, 0, sizeof(MutateImportThunkNode));
			
			if (!IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
			{	// STRING
				strcpy_s(tmpImpThunkNode.FuncName, (char*)RVAToPtr(_pImageBase, pThunk->u1.AddressOfData + 2));
			}
			else
			{	// ORDINAL
				tmpImpThunkNode.Ordinal = pThunk->u1.Ordinal;
			}
			
			tmpImportNode.vThunks.push_back(tmpImpThunkNode);

			pThunk++;
		}

		tmpImportNode.nFunc = tmpImportNode.vThunks.size();

		vMuateImport.push_back(tmpImportNode);

		pIID++;
	}

	
	/*
	FirstThunk|DLLName[32]|nFunc|FuncName[32]...
	*/
	/*  为变异输入表分配内存空间，并把输入表以变异后格式写入分配内存空间中  */
	_pMutateImportInfo->nMutateImport = CalcMutateImpSize(vMuateImport);
	_pMutateImportInfo->pMutateImport = new char[_pMutateImportInfo->nMutateImport];
	memset(_pMutateImportInfo->pMutateImport, 0, _pMutateImportInfo->nMutateImport);
	char* pData = (char*)(_pMutateImportInfo->pMutateImport);
	for (std::vector<MutateImportNode>::iterator iterD = vMuateImport.begin(); iterD < vMuateImport.end(); iterD++)
	{
		*(DWORD*)pData = iterD->FirstThunk;
		pData += sizeof(DWORD);
		strcpy_s(pData, 32, iterD->DLLName);
		pData += 32 * sizeof(char);
		*(DWORD*)pData = iterD->nFunc;
		pData += sizeof(DWORD);
		for (std::vector<MutateImportThunkNode>::iterator iterT = iterD->vThunks.begin(); iterT < iterD->vThunks.end(); iterT++)
		{
			memcpy(pData, iterT->FuncName, sizeof(*iterT));
			pData += sizeof(*iterT);
		}
	}


	return ERR_SUCCESS;
}


/*
	Description:	计算变异输入表存放需要的大小
*/
unsigned long CalcMutateImpSize(std::vector<MutateImportNode> &_rvMuateImport)
{
	unsigned long ulMutateImpSize = 0;
	ulMutateImpSize += \
		2 * sizeof(DWORD) * _rvMuateImport.size() \
		+ 32 * sizeof(char) * _rvMuateImport.size();
	
	for (std::vector<MutateImportNode>::iterator iter = _rvMuateImport.begin(); iter < _rvMuateImport.end(); iter++)
	{
		ulMutateImpSize += 32 * sizeof(char) * iter->vThunks.size();
	}

	return ulMutateImpSize;
}
