#include <list>
#include <Windows.h>
#include "packing.h"
#include "aplib\aplib.h"
#include "error.h"
#include "pe_utilities.h"

#pragma comment (lib,"aplib\\aplib.lib")


std::list<PackInfoNode> PackInfoTable;

/*
	Description :	压缩文件处理
*/
int PackFile(HANDLE hFile, const void* imagebase)
{
	PIMAGE_NT_HEADERS				pNTHeaders = (PIMAGE_NT_HEADERS)getNTHeader(imagebase);
	PIMAGE_SECTION_HEADER			pSecHeaders = (PIMAGE_SECTION_HEADER)getSecHeader(imagebase);
	PIMAGE_DATA_DIRECTORY			pBoundImportDir = NULL;
	PIMAGE_DATA_DIRECTORY			pIATDir = NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR	pBoundImport = NULL;
	
	unsigned long nSectionNum = pNTHeaders->FileHeader.NumberOfSections;
	unsigned long nSize = 0;

	DWORD nbWritten;

	try
	{
		/*  数据目录-绑定输入 清零  */
		/*pBoundImportDir = &pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
		if (pBoundImportDir->VirtualAddress != NULL && pBoundImportDir->Size > 0)
		{
			pBoundImport = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)RVAToPtr(imagebase, pBoundImportDir->VirtualAddress);
			memset(pBoundImport, 0, pBoundImportDir->Size);
			pBoundImportDir->VirtualAddress = 0;
			pBoundImportDir->Size = 0;
		}*/


		/*  清除IAT信息  */
		/*pIATDir = &pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
		if (pIATDir->VirtualAddress != NULL)
		{
			memset(RVAToPtr(imagebase, pIATDir->VirtualAddress), 0, pIATDir->Size);
			pIATDir->VirtualAddress = 0;
			pIATDir->Size = 0;
		}*/


		
		//nSize = (unsigned long)(&pSecHeaders[pNTHeaders->FileHeader.NumberOfSections + 1]) - (unsigned long)imagebase;// 计算新的文件头的大小(己考虑增加一个区段）

		//nSize = AlignSize(nSize, pNTHeaders->OptionalHeader.FileAlignment);

		//pNTHeaders->OptionalHeader.SizeOfHeaders = nSize;// 要修正文件头中的SizeOfHeaders大小

		//pSecHeaders->PointerToRawData = nSize;// 同时还要修正第一个区块的RAW地址

		/*  把文件头写入文件  */
		//if (!WriteFile(hFile, (PCHAR)imagebase, nSize, &nbWritten, NULL))// 写入文件
		//{
		//	// log : "错误!文件写失败!
		//	CloseHandle(hFile);
		//	return ERR_INVALIDFILE;
		//}


		unsigned int nIndex;
		char* pCurSection;
		unsigned long nMinimalSize;
		char* pCurPacked = 0;
		unsigned long packedsize;
		unsigned long nRawSize = 0;
		/*  写入原各区块数据  */
		for (nIndex = 0; nIndex < pNTHeaders->FileHeader.NumberOfSections; nIndex++, pSecHeaders++)
		{

			pCurSection = RVAToPtr(imagebase, pSecHeaders->VirtualAddress);
			//nSize = pSecHeaders->SizeOfRawData;如果不融合区块可以用这个
			nSize = pSecHeaders->Misc.VirtualSize;


			// 注: 由于某些区块由于之前的一些擦除操作已经清除了部分数据，导致区块可能变小，
			// 因此这里通过搜索并去掉尾部无用的零字节，重新计算区块的大小
			nMinimalSize = CalcMinSizeOfData(pCurSection, nSize);

			// 如果整个区块已经只省零字节，则可以不需要保存此区块的数据
			if (nMinimalSize == 0)
			{
				pSecHeaders->SizeOfRawData = 0;
				pSecHeaders->Characteristics |= IMAGE_SCN_MEM_WRITE;

				// 由于压缩的原因，因此必须每次都修正下一个区块的起始偏移地址
				if (nIndex != nSectionNum - 1)
				{
					pSecHeaders[1].PointerToRawData = pSecHeaders->PointerToRawData + pSecHeaders->SizeOfRawData;
				}

				continue;
			}

			// 判断当前区块数据能否被压缩
			if (IsSectionPackable(pSecHeaders))
			{
				pCurPacked = new char[nMinimalSize];

				if (PackData(pCurSection, nMinimalSize, pCurPacked, &packedsize))
				{
					// log : "区块压缩成功"
				}
				else
				{
					// log : "压缩数据失败"
					return false;
				}

				// 写入压缩后的数据
				SetFilePointer(hFile, pSecHeaders->PointerToRawData, 0, FILE_BEGIN);
				if (!WriteFile(hFile, (PCHAR)pCurPacked, packedsize, &nbWritten, NULL))// 写入文件
				{
					// log : "错误!文件写失败!"
					CloseHandle(hFile);
					return ERR_INVALIDFILE;
				}

				
				// 写入为对齐而填充的零数据
				nRawSize = AlignSize(packedsize, pNTHeaders->OptionalHeader.FileAlignment);
				if (nRawSize - packedsize > 0)
				{
					for (unsigned int i = packedsize; i < nRawSize; i++)
					{
						WriteFile(hFile, "\0", 1, &nbWritten, NULL);
					}
				}

				// 修正区块的大小
				pSecHeaders->SizeOfRawData = nRawSize;

				// 记录压缩过的区块信息，用于外壳在运行时解压缩
				if (ERR_SUCCESS == AddPackInfo(pSecHeaders->VirtualAddress, pSecHeaders->Misc.VirtualSize, pSecHeaders->SizeOfRawData))
				{
					return true;
				}
			}
			else
			{
					nRawSize = AlignSize(nMinimalSize, pNTHeaders->OptionalHeader.FileAlignment);

					// 不能压缩的区块，则直接保存区块的数据
					if (!WriteFile(hFile, (PCHAR)pCurSection, nRawSize, &nbWritten, NULL))// 写入文件
					{
						// log : "错误!文件写失败!"
						CloseHandle(hFile);
						return ERR_INVALIDFILE;
					}

					pSecHeaders->SizeOfRawData = nRawSize;
			}

			// 由于压缩的原因，因此必须每次都修正下一个区块的起始偏移地址
			if (nIndex != nSectionNum - 1)
			{
				pSecHeaders[1].PointerToRawData = pSecHeaders->PointerToRawData + pSecHeaders->SizeOfRawData;
			}

			pSecHeaders->Characteristics |= IMAGE_SCN_MEM_WRITE;

		}
	}
	catch (...)
	{
		// log : "pack file failed"
		return ERR_UNKNOWN;
	}

	return ERR_SUCCESS;
}


/* 
	Description:	调用aplib压缩引擎压缩数据                                   
*/
bool PackData(
	const char* psrc, 
	const unsigned long srcsize, 
	char* pdes, 
	unsigned long *dessize)
{
	char* pworkmem = 0;
	unsigned int workmemsize = 0;

	try
	{
		// 计算工作空间大小
		workmemsize = aP_workmem_size(srcsize);

		// 申请工作空间
		pworkmem = new char[workmemsize];

		// 对原始数据进行压缩
		*dessize = aP_pack(psrc, pdes, srcsize, pworkmem, 0, 0);

		delete[]pworkmem;
	}
	catch (...)
	{
		// log : "未知异常."
		return false;

	}

	return true;
}


/*
	Description:
记录压缩过的区块信息，用于外壳在运行时解压缩
数据储存格式：
DWORD  保存区块原大小__解压所需空间大小
DWORD  保存区块原偏移__解压起点
DWORD  保存压缩后大小__解压数量

以后会保存在shell.asm变量：
S_PackSection	DB	0a0h dup (?)
*/
int AddPackInfo(
	unsigned long OriginalOffset, 
	unsigned long OriginalSize, 
	unsigned long nPackSize)
{
	try
	{
		PackInfoNode temp;
		temp.originaloffset = OriginalOffset;
		temp.originalsize = OriginalSize;
		temp.packsize = nPackSize;
		
		PackInfoTable.push_back(temp);
	}
	catch (...)
	{
		// log 
		return ERR_UNKNOWN;
	}

	return ERR_SUCCESS;
}