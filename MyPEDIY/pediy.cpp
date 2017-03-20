#include <windows.h>
#include "pediy.h"
#include "pe_utilities.h"
#include "error.h"
#include "config.h"
#include "relocation.h"
#include "import.h"
#include "section.h"
#include "extradata.h"
#include "packing.h"
#include "shell.h"


/*
	Description:	������������
	RetValue:		ERR_SUCCESS
					ERR_UNKNOWN
*/
int ProtTheFile(TCHAR *szFilePath)
{
	HANDLE hFile;
	void* pImageBase = 0;
	void* pExtraData = 0;
	void* pShellSection = 0;
	unsigned long ulExtraDataSize = 0;

	try
	{
		ISWORKING = true;
		
		/*  ���������ļ�  */
		if (ISCREATEBAK)
		{
			BackUpFile(szFilePath);
		}

		// 	��ȡ�ļ�������
		ReadFileToHeap(szFilePath, &hFile, &pImageBase);

		// FixPEHeader(pimagebase);
		
		/*  �������ݶ�ȡ  */
		if (ISSAVEDATA)
		{
			ReadExtraData(hFile, pImageBase, &pExtraData, &ulExtraDataSize);
		}

		CloseHandle(hFile);

		// log : �ļ��������


		/*  �����ض�λ����  */
		if (ISMUTATERELOC)
		{	 
			MutateRelocation();
		}


		/*  ��������  */
		MutateImportInfo MImpInfo = {0};
		if (ISMUTATEIMPORT)
		{
			MutateImport(pImageBase, &MImpInfo);
		}


		/*  �ϲ�����  */
		if (ISMERGESECTION)
		{
			MergeSection();
		}


		/* */
		hFile = CreateFile(
			szFilePath,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			return  FALSE;
		}


		/*  ���shell��  */
		std::vector<DataToShellNode> vDTS;
		DataToShellNode tmpDTSN;
		if (ISMUTATEIMPORT)
		{
			tmpDTSN.DataType = ShellDataType::MImp;
			tmpDTSN.pData = MImpInfo.pMutateImport;
			tmpDTSN.nData = MImpInfo.nMutateImport;
			vDTS.push_back(tmpDTSN);
		}
		ImployShell(pImageBase, vDTS, &pShellSection);


		/*  �ں��ڴ�� */
		void* pNewImage = MergeMemBlock(pImageBase, pShellSection);
		delete[]pImageBase;
		pImageBase = pNewImage;
		pNewImage = 0;


		/*  ѹ����������  */
		PackFile(pImageBase);
	

		/*  �Ѷ�������д���ļ�  */
		// TODO : mergememblock
		WriteHeapToFile(hFile, pImageBase);


		/*  д���������  */
		if (ISSAVEDATA)
		{
			WriteExtraData(hFile, pExtraData, ulExtraDataSize);
		}

		/*  �������,����  */
		if (0 != pImageBase) delete []pImageBase;
		if (0 != pShellSection) delete []pShellSection;
		if (0 != MImpInfo.pMutateImport)	delete[]MImpInfo.pMutateImport;
		//if (ISPACKRES)	delete []pMapOfPackRes;
		if (0 != pExtraData)	delete []pExtraData;

		CloseHandle(hFile);

		ISWORKING = false;
	}
	catch (...)
	{
		// TODO: �����쳣�Ķ�ջƽ����
		MessageBox(NULL, TEXT("�����ļ������г��ִ���."), NULL, 0);
		return ERR_UNKNOWN;
	}

	return ERR_SUCCESS;
}


/*
Description:	�ж��ļ��Ƿ�Ϊ��ЧPE�ļ�
RetValue:		ERR_INVALIDFILE
ERR_SUCCESS
*/
int IsPEFile(TCHAR *szFilePath)
{

	DWORD					fileSize;
	HANDLE					hMapping;
	LPVOID					pFileMap;
	PIMAGE_DOS_HEADER	    pDosHeader = NULL;
	PIMAGE_NT_HEADERS       pNtHeader = NULL;
	PIMAGE_FILE_HEADER      pFilHeader = NULL;
	PIMAGE_OPTIONAL_HEADER  pOptHeader = NULL;
	PIMAGE_SECTION_HEADER   pSecHeader = NULL;


	//���ļ�
	HANDLE hFile = CreateFile(
		szFilePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return	ERR_INVALIDFILE;
	}

	//����ļ����� :
	fileSize = GetFileSize(hFile, NULL);
	if (fileSize == 0xFFFFFFFF)
	{
		return	ERR_INVALIDFILE;
	}

	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMapping)
	{
		CloseHandle(hFile);

		return ERR_INVALIDFILE;
	}

	pFileMap = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (NULL == pFileMap)
	{
		CloseHandle(hMapping);
		CloseHandle(hFile);

		return ERR_INVALIDFILE;
	}

	// ����DOS��־
	pDosHeader = (PIMAGE_DOS_HEADER)pFileMap;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return ERR_INVALIDFILE;
	}

	// ����NT��־
	pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return ERR_INVALIDFILE;
	}

	// �Ƿ�ֻ��һ������
	pFilHeader = &pNtHeader->FileHeader;
	if (pFilHeader->NumberOfSections == 1)
	{
		return ERR_INVALIDFILE;
	}

	pOptHeader = &pNtHeader->OptionalHeader;//�õ�IMAGE_OPTIONAL_HEADER�ṹָ��ĺ���
											// pOptHeader->AddressOfEntryPoint;

											//�õ���һ���������ʼ��ַ  
	pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);
	pSecHeader++;//�õ��ڶ����������ʼ��ַ
				 // ��� ������ڵ��ַ �� �ڶ���������ʼ��ַ ��
	if ((pOptHeader->AddressOfEntryPoint) > (pSecHeader->VirtualAddress)) {
		return ERR_INVALIDFILE;
	}

	if (((pFilHeader->Characteristics) & IMAGE_FILE_DLL) != 0)
	{
		// DLL
	}
	else
	{
		// EXE
	}

	UnmapViewOfFile(pFileMap);
	CloseHandle(hMapping);
	CloseHandle(hFile);

	return ERR_SUCCESS;
}


/*
	Description:	��ȡĿ���ļ������У�����Ӱ��ʽ
	Parameters:		TCHAR *szFilePath	in:�ļ�·��
					HANDLE *hFile		out:
					void **imagebase	out:
*/
int ReadFileToHeap(TCHAR *szFilePath, HANDLE *_hfile, void **_pimagebase)
{
	HANDLE hFile;
	IMAGE_DOS_HEADER dosheader;
	IMAGE_NT_HEADERS ntheader;
	PIMAGE_SECTION_HEADER psecheader;
	DWORD	RWbytes;
	unsigned long imagesize_fix;
	void* pimagebase;
	BOOL bRetCode;

	hFile = CreateFile(
		szFilePath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return  FALSE;
	}

	// ����ڶ�������
	*_hfile = hFile;

	/*  ��ȡ�ļ�ͷ��ȡ�ļ���Ϣ  */

	// ��DOSͷ 
	bRetCode = ReadFile(hFile, &dosheader, sizeof(dosheader), &RWbytes, NULL);
	if (FALSE == bRetCode)
	{
		return ERR_INVALIDFILE;
	}

	// ��λ��PEͷ��ʼ��e_lfanew
	SetFilePointer(hFile, dosheader.e_lfanew, NULL, FILE_BEGIN);

	// ����PEͷ
	bRetCode = ReadFile(hFile, &ntheader, sizeof(ntheader), &RWbytes, NULL);
	if (FALSE == bRetCode)
	{
		return ERR_INVALIDFILE;
	}

	// �������ܴ��ڵ�ӳ���Сû�ж�������
	imagesize_fix = AlignSize(ntheader.OptionalHeader.SizeOfImage, ntheader.OptionalHeader.SectionAlignment);

	// �����ڴ����ڱ���ӳ��
	pimagebase = new unsigned char[imagesize_fix];
	if (pimagebase == NULL)
	{
		// log : ����!�ڴ治�㣡
		return ERR_OUTOFMEM;
	}
	*_pimagebase = pimagebase;

	memset(pimagebase, 0, imagesize_fix);

	// ���ȶ�λ����PE�ļ�ͷ���ڴ���
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	bRetCode = ReadFile(hFile, pimagebase, ntheader.OptionalHeader.SizeOfHeaders, &RWbytes, NULL);
	if (FALSE == bRetCode)
	{
		return ERR_INVALIDFILE;
	}

	// ѭ�����ζ����������ݵ�ӳ���е������ַ��
	psecheader = getSecHeader(pimagebase);
	for (unsigned int index = 0; 
		index < ntheader.FileHeader.NumberOfSections; 
		++index, ++psecheader)
	{
		// ��λ��SECTION������ʼ��
		SetFilePointer(hFile, psecheader->PointerToRawData, NULL, FILE_BEGIN);

		// ��SECTION���ݵ�ӳ����
		bRetCode = ReadFile(
			hFile, 
			&((char*)pimagebase)[psecheader->VirtualAddress], 
			psecheader->SizeOfRawData, &RWbytes, 
			NULL);
		if (FALSE == bRetCode)
		{
			return ERR_INVALIDFILE;
		}
	}

	return ERR_SUCCESS;
}


/*
	Description:	�����ݴӶ�д�뵽�ļ�
	// ע�������ǰ������ڴ�ӳ�䷽ʽ�洢�ģ�д��ʱ��Ҫע�������ַ
*/
int WriteHeapToFile(HANDLE _hFile, void* _pImageBase)
{
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)getNTHeader(_pImageBase);
	DWORD BytesRW;


	// д��PEͷ
	SetFilePointer(_hFile, 0, NULL, FILE_BEGIN);
	WriteFile(_hFile, _pImageBase, pNTHeader->OptionalHeader.SizeOfHeaders, &BytesRW, NULL);

	// д�������
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)getSecHeader(_pImageBase);
	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, pSecHeader++)
	{
		SetFilePointer(_hFile, pSecHeader->PointerToRawData, 0, FILE_BEGIN);
		WriteFile(_hFile, RVAToPtr(_pImageBase, pSecHeader->VirtualAddress), pSecHeader->SizeOfRawData, &BytesRW, NULL);
	}

	return ERR_SUCCESS;
}


/*
	Description:	����PEͷ��Ϣ
*/
int FixPEHeader(void *_pimagebase)
{
	PIMAGE_DOS_HEADER pdosheader = (PIMAGE_DOS_HEADER)_pimagebase;;
	PIMAGE_NT_HEADERS pntheader = (PIMAGE_NT_HEADERS)getNTHeader(_pimagebase);
	PIMAGE_SECTION_HEADER psecheader = (PIMAGE_SECTION_HEADER)getSecHeader(_pimagebase);
	PIMAGE_SECTION_HEADER psecheader_iterator;

	unsigned long sectionnum = pntheader->FileHeader.NumberOfSections;
	unsigned int index;

	// �Դ洢�ڶ��е���������ݽ�������
	// ÿ��������е�SizeOfRawData, VirtualSize
	for (index = 0, psecheader_iterator = psecheader; index < sectionnum; ++index, ++psecheader_iterator)
	{
		// �������ܴ��ڵĶ�������
		psecheader_iterator->SizeOfRawData = AlignSize(psecheader_iterator->SizeOfRawData, pntheader->OptionalHeader.FileAlignment);
		psecheader_iterator->Misc.VirtualSize = AlignSize(psecheader_iterator->Misc.VirtualSize, pntheader->OptionalHeader.SectionAlignment);
	}

	return ERR_SUCCESS;
}


