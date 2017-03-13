#include <windows.h>
#include "relocation.h"


/*
	Description:	�ض�λ����촦����
*/
bool MutateRelocation()
{
#ifdef __RELOCATION_SWITCH__
	PIMAGE_DATA_DIRECTORY		pRelocDir = NULL;
	PIMAGE_BASE_RELOCATION2		pBaseReloc = NULL;

	PCHAR						pRelocBufferMap = NULL;
	PCHAR						pData = NULL;
	UINT						nRelocSize = NULL;
	UINT						nSize = 0;
	UINT						nType = 0;
	UINT						nIndex = 0;
	UINT						nTemp = 0;
	UINT						nNewItemOffset = 0;
	UINT						nNewItemSize = 0;


	pRelocDir = &m_pntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	nRelocSize = pRelocDir->Size;
	pBaseReloc = (PIMAGE_BASE_RELOCATION2)RVAToPtr(pRelocDir->VirtualAddress);

	// ���û���ض�λ���ݣ���ֱ�ӷ���
	if (pRelocDir->VirtualAddress == 0)
	{
		return TRUE;
	}
	//������ʱ����ռ�
	pRelocBufferMap = new char[nRelocSize];
	if (pRelocBufferMap == NULL)
	{
		return FALSE;
	}
	ZeroMemory(pRelocBufferMap, nRelocSize);

	// 
	pData = pRelocBufferMap;

	while (pBaseReloc->VirtualAddress != 0)
	{
		nNewItemSize = (pBaseReloc->SizeOfBlock - 8) / 2;//������������Ҫ���ֽڳ�

		while (nNewItemSize != 0)
		{
			nType = pBaseReloc->TypeOffset[nIndex] >> 0x0c;//ȡtype

			if (nType == 0x3)
			{
				//ȡ��ItemOffset�����ϱ����ض�λ��ʼ��ַ ����ȥnTemp,�õ���ֵ׼���ŵ����ض�λ��ṹ��
				nNewItemOffset = ((pBaseReloc->TypeOffset[nIndex] & 0x0fff) + pBaseReloc->VirtualAddress) - nTemp;
				if (nNewItemOffset > 0xff)//����Ǳ����ض�λ���ݵ�һ��
				{
					*(BYTE *)(pData) = 3;
					pData += sizeof(BYTE);
					*(DWORD *)pData = (DWORD)(nNewItemOffset);
					pData += sizeof(DWORD);

				}
				else
				{
					*(BYTE *)(pData) = (BYTE)(nNewItemOffset);
					pData += sizeof(BYTE);
				}
				nTemp += nNewItemOffset;
			}
			nNewItemSize--;
			nIndex++;
		}

		nIndex = 0;
		pBaseReloc = (PIMAGE_BASE_RELOCATION2)((DWORD)pBaseReloc + pBaseReloc->SizeOfBlock);
	}

	memset((PCHAR)RVAToPtr(pRelocDir->VirtualAddress), 0, nRelocSize);
	memcpy((PCHAR)RVAToPtr(pRelocDir->VirtualAddress), pRelocBufferMap, nRelocSize);
	delete pRelocBufferMap;

#endif // __RELOCATION_SWITCH__
	return true;
}