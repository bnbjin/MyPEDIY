#include <windows.h>
#include "pe_utilities.h"
#include "error.h"

/*
	Description:	取整对齐函数
*/
UINT AlignSize(UINT nSize, UINT nAlign)
{
	return ((nSize + nAlign - 1) / nAlign * nAlign);
}


/* 
	Description:	RVA->指向堆中对应位置的指针						   
*/
char* RVAToPtr(const void* imagebase, const unsigned long dwRVA)
{
	return ((char*)imagebase + dwRVA);
}


/*
	Description:	获取NT头指针
*/
PIMAGE_NT_HEADERS getNTHeader(const void* imagebase)
{
	return (PIMAGE_NT_HEADERS)((char*)imagebase + ((PIMAGE_DOS_HEADER)imagebase)->e_lfanew);
}

/*
	Description:	获取section表指针
*/
PIMAGE_SECTION_HEADER getSecHeader(const void* _imagebase)
{
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)getNTHeader(_imagebase);

	return (PIMAGE_SECTION_HEADER)((char*)pNTHeaders + sizeof(IMAGE_NT_HEADERS));
	
}


/*
	Description:	获取最后一个区块表项指针
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
	Description:	搜索并去掉尾部无用的零字节，重新计算区块的大小             
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
	Description:	判断当前区块数据能否被压缩
*/
bool IsSectionPackable(PIMAGE_SECTION_HEADER pSecHeader)
{
	// 如果发现匹配的区块名称，则表示此区块可以压缩
	for (UINT nIndex = 0; nIndex < nListNum; nIndex++)
	{

		/*有些输出表可能会在.rdata等区块，如果区块合并了就不能这样判断了
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
	Description:	备份文件
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
	Description:	获取DOS头大小
*/
unsigned int GetDosHeaderSize(void* _pImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_pImageBase;

	return pDosHeader->e_lfanew;
}


/*
	Description:	获取NT头大小
*/
unsigned int GetNTHeaderSize(void* _pImageBase)
{
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)getNTHeader(_pImageBase);

	unsigned int NTHeaderSize = sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pNTHeader->FileHeader.SizeOfOptionalHeader;

	return NTHeaderSize;
}


/*
	Description:	获取区块表大小
*/
unsigned int GetSectionTableSize(void* _pImageBase)
{
	return 0;
}