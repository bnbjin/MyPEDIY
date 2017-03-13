#include <windows.h>
#include "pe_utilities.h"
#include "error.h"

/*
	Description:	ȡ�����뺯��
*/
UINT AlignSize(UINT nSize, UINT nAlign)
{
	return ((nSize + nAlign - 1) / nAlign * nAlign);
}


/* 
	Description:	RVA->ָ����ж�Ӧλ�õ�ָ��						   
*/
char* RVAToPtr(const void* imagebase, const unsigned long dwRVA)
{
	return ((char*)imagebase + dwRVA);
}


/*
	Description:	��ȡNTͷָ��
*/
PIMAGE_NT_HEADERS getNTHeader(const void* imagebase)
{
	return (PIMAGE_NT_HEADERS)((char*)imagebase + ((PIMAGE_DOS_HEADER)imagebase)->e_lfanew);
}

/*
	Description:	��ȡsection��ָ��
*/
PIMAGE_SECTION_HEADER getSecHeader(const void* _imagebase)
{
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)getNTHeader(_imagebase);

	return (PIMAGE_SECTION_HEADER)((char*)pNTHeaders + sizeof(IMAGE_NT_HEADERS));
	
}


/*
	Description:	��ȡ���һ���������ָ��
*/
PIMAGE_SECTION_HEADER getLastSecHeader(const void* _pImageBase)
{
	PIMAGE_SECTION_HEADER pSecHeader = getSecHeader(_pImageBase);

	while (0 == pSecHeader->PointerToRawData && 0 == pSecHeader->SizeOfRawData)
	{
		pSecHeader++;
	}

	return --pSecHeader;
}


/*
	Description:	������ȥ��β�����õ����ֽڣ����¼�������Ĵ�С             
*/
unsigned int CalcMinSizeOfData(char* pSectionData, const unsigned int nSectionSize)
{

	if (IsBadReadPtr(pSectionData, nSectionSize))
	{
		return nSectionSize;
	}

	char*	pData = pSectionData + nSectionSize - 1;
	unsigned int	nSize = nSectionSize;

	while (nSize > 0 && *pData == 0)
	{
		pData--;
		nSize--;
	}

	return nSize;
}


const int nListNum = 6;
const char* szSecNameList[nListNum] =
{
	".text",
	".data",
	".rdata",
	"CODE",
	"DATA",
	".reloc"
};
/*
	Description:	�жϵ�ǰ���������ܷ�ѹ��
*/
bool IsSectionPackable(PIMAGE_SECTION_HEADER pSecHeader)
{
	// �������ƥ����������ƣ����ʾ���������ѹ��
	for (UINT nIndex = 0; nIndex < nListNum; nIndex++)
	{

		/*��Щ�������ܻ���.rdata�����飬�������ϲ��˾Ͳ��������ж���
		if (!IsMergeSection)
		{
			if ((nExportAddress >= pSecHeader->VirtualAddress) && (nExportAddress < (pSecHeader->VirtualAddress + pSecHeader->Misc.VirtualSize)))
				return FALSE;
		}
		*/

		if (strncmp((char *)pSecHeader->Name, szSecNameList[nIndex], strlen(szSecNameList[nIndex])) == 0)
		{
			return true;
		}
	}

	return false;
}


/*
	Description:	�����ļ�
*/
int BackUpFile(TCHAR *szFilePath)
{
	TCHAR *szFilebakName = new TCHAR[MAX_PATH * sizeof(TCHAR)];
	
	ZeroMemory(szFilebakName, MAX_PATH * sizeof(TCHAR));

	lstrcpy(szFilebakName, szFilePath);
	lstrcat(szFilebakName, TEXT(".bak"));
	CopyFile(szFilePath, szFilebakName, FALSE);

	delete []szFilebakName;

	return ERR_SUCCESS;
}

/*
	Description:	��ȡDOSͷ��С
*/
unsigned int GetDosHeaderSize(void* _pImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_pImageBase;

	return pDosHeader->e_lfanew;
}


/*
	Description:	��ȡNTͷ��С
*/
unsigned int GetNTHeaderSize(void* _pImageBase)
{
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)getNTHeader(_pImageBase);

	unsigned int NTHeaderSize = sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pNTHeader->FileHeader.SizeOfOptionalHeader;

	return NTHeaderSize;
}


/*
	Description:	��ȡ������С
*/
unsigned int GetSectionTableSize(void* _pImageBase)
{
	return 0;
}