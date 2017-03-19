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

	while (0 != pSecHeader->PointerToRawData && 0 != pSecHeader->SizeOfRawData)
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
	// TODO
	return ERR_SUCCESS;
}


/*
	Description:	�������������������,new�����������ڴ棬��Ҫ������delete
*/
unsigned int CreateNewSection(void* _pImageBase, const unsigned long _secsize, void **_ppNewSection)
{
	PIMAGE_NT_HEADERS pNTHeader = getNTHeader(_pImageBase);
	PIMAGE_SECTION_HEADER pNewSecHeader = getLastSecHeader(_pImageBase) + 1;
	PIMAGE_SECTION_HEADER pLastSecHeader = getLastSecHeader(_pImageBase);

	/*  ���������������ƶ�  */
	/* �����һ�����鿪ʼ�����һ�������ƶ�*/
	/*
	
	for (int i = pNTHeader->FileHeader.NumberOfSections; i > 0; i--, pLastSecHeader--)
	{
		memcpy(pLastSecHeader + 1, pLastSecHeader, sizeof(IMAGE_SECTION_HEADER));
	}*/


	/*  ��д��������Ϣ  */
	memset(pNewSecHeader, 0, sizeof(IMAGE_SECTION_HEADER));
	/* Name, VirtualAddress, VirtualSize, RawAddress, RawSize, Characteristics */
	char secname[8] = { ".shell" };
	memcpy(pNewSecHeader->Name, ".shell", 8);
	pNewSecHeader->VirtualAddress = pLastSecHeader->VirtualAddress + AlignSize(pLastSecHeader->Misc.VirtualSize, pNTHeader->OptionalHeader.SectionAlignment);
	pNewSecHeader->Misc.VirtualSize = AlignSize(_secsize, pNTHeader->OptionalHeader.SectionAlignment);
	pNewSecHeader->PointerToRawData = pLastSecHeader->PointerToRawData + AlignSize(pLastSecHeader->SizeOfRawData, pNTHeader->OptionalHeader.FileAlignment);
	pNewSecHeader->SizeOfRawData = AlignSize(_secsize, pNTHeader->OptionalHeader.FileAlignment);
	pNewSecHeader->Characteristics = 0xE0000020;


	/*  �����������ڴ�  */
	unsigned long ulNewSecSize = AlignSize(_secsize, pNTHeader->OptionalHeader.SectionAlignment);
	*_ppNewSection = new char[ulNewSecSize];
	memset(*_ppNewSection, 0, ulNewSecSize);


	/*  �޸�PEͷ�����  */
	/* SizeOfImage, NumberOfSections, SizeOfCode */
	pNTHeader->OptionalHeader.SizeOfImage = AlignSize(pNTHeader->OptionalHeader.SizeOfImage + ulNewSecSize, pNTHeader->OptionalHeader.SectionAlignment);
	pNTHeader->FileHeader.NumberOfSections++;
	pNTHeader->OptionalHeader.SizeOfCode += ulNewSecSize;


	return ERR_SUCCESS;
}


/*
	Description:	��������ڴ���ںϵ�һ��
*/
void* MergeMemBlock(void* _pImageBase, void* _pShellSection)
{
	PIMAGE_NT_HEADERS pNTHeader = getNTHeader(_pImageBase);
	PIMAGE_SECTION_HEADER pShellSecHeader = getLastSecHeader(_pImageBase);
	unsigned long ulNewImageSize = pNTHeader->OptionalHeader.SizeOfImage;
	unsigned long ulOriginalImageSize = ulNewImageSize - AlignSize(pShellSecHeader->Misc.VirtualSize, pNTHeader->OptionalHeader.SectionAlignment);
	unsigned long ulShellSize = pShellSecHeader->SizeOfRawData;

	// ������ӳ����ڴ�ռ�
	void* pNewMemBlock = new unsigned char[ulNewImageSize];
	memset(pNewMemBlock, 0, ulNewImageSize);

	// ����ԭImageBase
	memcpy(pNewMemBlock, _pImageBase, ulOriginalImageSize);

	// ����ShellSection
	void* pNewShellPosition = (void*)((unsigned long)pNewMemBlock + ulOriginalImageSize);
	memcpy(pNewShellPosition, _pShellSection, ulShellSize);

	return pNewMemBlock;
}


/*
	Description:	��ԭ�������������������Ϊ��д
*/
int	MakeOriginalImportSecWritable(void *_pImageBase)
{
	PIMAGE_NT_HEADERS pNTHeader = getNTHeader(_pImageBase);
	PIMAGE_SECTION_HEADER pSecHeader = getSecHeader(_pImageBase);
	IMAGE_DATA_DIRECTORY ImpD = (IMAGE_DATA_DIRECTORY)(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	while (!(
		ImpD.VirtualAddress >= pSecHeader->VirtualAddress \
		&& ImpD.VirtualAddress <= (pSecHeader->VirtualAddress + pSecHeader->Misc.VirtualSize)))
	{
		pSecHeader++;
	}
	if (ImpD.VirtualAddress >= pSecHeader->VirtualAddress \
		&& ImpD.VirtualAddress <= (pSecHeader->VirtualAddress + pSecHeader->Misc.VirtualSize))
	{
		pSecHeader->Characteristics |= IMAGE_SCN_MEM_WRITE;
	}

	return ERR_SUCCESS;
}