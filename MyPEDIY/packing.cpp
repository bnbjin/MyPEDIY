#include <list>
#include <Windows.h>
#include "packing.h"
#include "aplib\aplib.h"
#include "error.h"
#include "pe_utilities.h"

#pragma comment (lib,"aplib\\aplib.lib")


std::list<PackInfoNode> PackInfoTable;

/*
	Description :	ѹ���ļ�����
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
		/*  ����Ŀ¼-������ ����  */
		/*pBoundImportDir = &pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
		if (pBoundImportDir->VirtualAddress != NULL && pBoundImportDir->Size > 0)
		{
			pBoundImport = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)RVAToPtr(imagebase, pBoundImportDir->VirtualAddress);
			memset(pBoundImport, 0, pBoundImportDir->Size);
			pBoundImportDir->VirtualAddress = 0;
			pBoundImportDir->Size = 0;
		}*/


		/*  ���IAT��Ϣ  */
		/*pIATDir = &pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
		if (pIATDir->VirtualAddress != NULL)
		{
			memset(RVAToPtr(imagebase, pIATDir->VirtualAddress), 0, pIATDir->Size);
			pIATDir->VirtualAddress = 0;
			pIATDir->Size = 0;
		}*/


		
		//nSize = (unsigned long)(&pSecHeaders[pNTHeaders->FileHeader.NumberOfSections + 1]) - (unsigned long)imagebase;// �����µ��ļ�ͷ�Ĵ�С(����������һ�����Σ�

		//nSize = AlignSize(nSize, pNTHeaders->OptionalHeader.FileAlignment);

		//pNTHeaders->OptionalHeader.SizeOfHeaders = nSize;// Ҫ�����ļ�ͷ�е�SizeOfHeaders��С

		//pSecHeaders->PointerToRawData = nSize;// ͬʱ��Ҫ������һ�������RAW��ַ

		/*  ���ļ�ͷд���ļ�  */
		//if (!WriteFile(hFile, (PCHAR)imagebase, nSize, &nbWritten, NULL))// д���ļ�
		//{
		//	// log : "����!�ļ�дʧ��!
		//	CloseHandle(hFile);
		//	return ERR_INVALIDFILE;
		//}


		unsigned int nIndex;
		char* pCurSection;
		unsigned long nMinimalSize;
		char* pCurPacked = 0;
		unsigned long packedsize;
		unsigned long nRawSize = 0;
		/*  д��ԭ����������  */
		for (nIndex = 0; nIndex < pNTHeaders->FileHeader.NumberOfSections; nIndex++, pSecHeaders++)
		{

			pCurSection = RVAToPtr(imagebase, pSecHeaders->VirtualAddress);
			//nSize = pSecHeaders->SizeOfRawData;������ں�������������
			nSize = pSecHeaders->Misc.VirtualSize;


			// ע: ����ĳЩ��������֮ǰ��һЩ���������Ѿ�����˲������ݣ�����������ܱ�С��
			// �������ͨ��������ȥ��β�����õ����ֽڣ����¼�������Ĵ�С
			nMinimalSize = CalcMinSizeOfData(pCurSection, nSize);

			// ������������Ѿ�ֻʡ���ֽڣ�����Բ���Ҫ��������������
			if (nMinimalSize == 0)
			{
				pSecHeaders->SizeOfRawData = 0;
				pSecHeaders->Characteristics |= IMAGE_SCN_MEM_WRITE;

				// ����ѹ����ԭ����˱���ÿ�ζ�������һ���������ʼƫ�Ƶ�ַ
				if (nIndex != nSectionNum - 1)
				{
					pSecHeaders[1].PointerToRawData = pSecHeaders->PointerToRawData + pSecHeaders->SizeOfRawData;
				}

				continue;
			}

			// �жϵ�ǰ���������ܷ�ѹ��
			if (IsSectionPackable(pSecHeaders))
			{
				pCurPacked = new char[nMinimalSize];

				if (PackData(pCurSection, nMinimalSize, pCurPacked, &packedsize))
				{
					// log : "����ѹ���ɹ�"
				}
				else
				{
					// log : "ѹ������ʧ��"
					return false;
				}

				// д��ѹ���������
				SetFilePointer(hFile, pSecHeaders->PointerToRawData, 0, FILE_BEGIN);
				if (!WriteFile(hFile, (PCHAR)pCurPacked, packedsize, &nbWritten, NULL))// д���ļ�
				{
					// log : "����!�ļ�дʧ��!"
					CloseHandle(hFile);
					return ERR_INVALIDFILE;
				}

				
				// д��Ϊ���������������
				nRawSize = AlignSize(packedsize, pNTHeaders->OptionalHeader.FileAlignment);
				if (nRawSize - packedsize > 0)
				{
					for (unsigned int i = packedsize; i < nRawSize; i++)
					{
						WriteFile(hFile, "\0", 1, &nbWritten, NULL);
					}
				}

				// ��������Ĵ�С
				pSecHeaders->SizeOfRawData = nRawSize;

				// ��¼ѹ������������Ϣ���������������ʱ��ѹ��
				if (ERR_SUCCESS == AddPackInfo(pSecHeaders->VirtualAddress, pSecHeaders->Misc.VirtualSize, pSecHeaders->SizeOfRawData))
				{
					return true;
				}
			}
			else
			{
					nRawSize = AlignSize(nMinimalSize, pNTHeaders->OptionalHeader.FileAlignment);

					// ����ѹ�������飬��ֱ�ӱ������������
					if (!WriteFile(hFile, (PCHAR)pCurSection, nRawSize, &nbWritten, NULL))// д���ļ�
					{
						// log : "����!�ļ�дʧ��!"
						CloseHandle(hFile);
						return ERR_INVALIDFILE;
					}

					pSecHeaders->SizeOfRawData = nRawSize;
			}

			// ����ѹ����ԭ����˱���ÿ�ζ�������һ���������ʼƫ�Ƶ�ַ
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
	Description:	����aplibѹ������ѹ������                                   
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
		// ���㹤���ռ��С
		workmemsize = aP_workmem_size(srcsize);

		// ���빤���ռ�
		pworkmem = new char[workmemsize];

		// ��ԭʼ���ݽ���ѹ��
		*dessize = aP_pack(psrc, pdes, srcsize, pworkmem, 0, 0);

		delete[]pworkmem;
	}
	catch (...)
	{
		// log : "δ֪�쳣."
		return false;

	}

	return true;
}


/*
	Description:
��¼ѹ������������Ϣ���������������ʱ��ѹ��
���ݴ����ʽ��
DWORD  ��������ԭ��С__��ѹ����ռ��С
DWORD  ��������ԭƫ��__��ѹ���
DWORD  ����ѹ�����С__��ѹ����

�Ժ�ᱣ����shell.asm������
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