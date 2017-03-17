#include <list>
#include <Windows.h>
#include "packing.h"
#include "aplib\aplib.h"
#include "pe_utilities.h"
#include "shell.h"

#pragma comment (lib, "aplib\\aplib.lib")


/*
	Description :	ѹ���ļ�ӳ���е�����
					Ĭ�ϰ����һ��������Ϊshell
					Ĭ�ϰѱ������ݷŵ�shell��
*/
int PackFile(void *_pImageBase, void *_pMutateImp, void *_pMutateReloc, void *_pMutateTLS)
{
	std::list<PackInfoNode> lstPackInfoTable;


	/*  �����������  */
	if (0 != _pMutateImp)
	{
		// TODO:
	}

	if (0 != _pMutateReloc)
	{
		// TODO:
	}

	if (0 != _pMutateTLS)
	{
		// TODO:
	}


	/*  ѹ���ڶ���shell(Luanch)  */
	PIMAGE_NT_HEADERS pNTHeader = getNTHeader(_pImageBase);
	PIMAGE_SECTION_HEADER pLastSection = getLastSecHeader(_pImageBase);
	void *pLuanch = RVAToPtr(_pImageBase, pLastSection->VirtualAddress) \
		+ (unsigned long)(&Label_Luanch_Start) \
		- (unsigned long)(&Label_Shell_Start);
	unsigned long nLuanchSize = (unsigned long)(&Label_Luanch_End) - (unsigned long)(&Label_Luanch_Start);
	PackInfoNode PIN;
	memset(&PIN, 0, sizeof(PackInfoNode));
	PIN.OriginalOffset = pLuanch;
	PIN.OriginalSize = nLuanchSize;
	PIN.PackedOffset = new char[nLuanchSize];
	PackData(&PIN);
	/* ѹ����ɣ����������д��ӳ�� */
	memset(pLuanch, 0, nLuanchSize);
	memcpy(pLuanch, PIN.PackedOffset, PIN.PackedSize);
	PInduction_Data pInduction_Data = (PInduction_Data) \
		(RVAToPtr(_pImageBase, pLastSection->VirtualAddress) \
			+ (unsigned long)(&Label_Induction_Data_Start) \
			- (unsigned long)(&Label_Shell_Start));
	pInduction_Data->nLuanchOriginalSize = nLuanchSize;
	pInduction_Data->nLuanchPackSize = PIN.PackedSize;
	delete[]PIN.PackedOffset;


	/*  ����ӳ���С������ֶ�  */
	// TODO��

	
	return ERR_SUCCESS;
}


/* 
	Description:	����aplibѹ������ѹ������                                   
*/
int PackData(PackInfoNode *_pPIN)
{
	char* pworkmem = 0;
	unsigned int workmemsize = 0;

	try
	{
		// ���㹤���ռ��С
		workmemsize = aP_workmem_size(_pPIN->OriginalSize);

		// ���빤���ռ�
		pworkmem = new char[workmemsize];

		// ��ԭʼ���ݽ���ѹ��
		_pPIN->PackedSize = aP_pack(_pPIN->OriginalOffset, _pPIN->PackedOffset, _pPIN->OriginalSize, pworkmem, 0, 0);

		delete[]pworkmem;
	}
	catch (...)
	{
		// log : "δ֪�쳣."
		return ERR_UNKNOWN;

	}

	return ERR_SUCCESS;
}
