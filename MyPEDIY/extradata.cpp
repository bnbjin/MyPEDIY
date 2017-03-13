#include <windows.h>
#include "extradata.h"
#include "error.h"
#include "pe_utilities.h"


/*
	Description:	���ļ��ж�ȡ��������
	Parameters:		[in]HANDLE	_hFile
					[in]void*	_imagebase
					[out]void**  _pExtraData
					[out]unsigned long*	_ulExtraDataSize
*/
int ReadExtraData(HANDLE _hFile, void* _imagebase, void **_pExtraData, unsigned long *_ulExtraDataSize)
{
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)getSecHeader(_imagebase);

	DWORD dwSizeH = 0;
	DWORD dwSizeL = 0;
	unsigned long ulExtraDataSize = 0;
	void *pExtraData = 0;
	DWORD BytesRW;


	dwSizeL = GetFileSize(_hFile, &dwSizeH);

	ulExtraDataSize = dwSizeL - (pSecHeader->PointerToRawData + pSecHeader->SizeOfRawData);
	
	if (ulExtraDataSize>0)
	{
		pExtraData = new char[ulExtraDataSize];
		
		memset(pExtraData, 0, ulExtraDataSize);

		ReadFile(_hFile, pExtraData, ulExtraDataSize, &BytesRW, NULL);
		// log : �������ݶ�ȡ���.
	}
	else
	{
		// log : û�ж�������.
	}

	*_pExtraData = pExtraData;
	*_ulExtraDataSize = ulExtraDataSize;

	return ERR_SUCCESS;
}


/*
	Description:	�Ѷ�������д���ļ�
*/
int WriteExtraData(HANDLE _hFile, void *_pExtraData, unsigned long ulExtraDataSize)
{
	DWORD BytesRW;

	SetFilePointer(_hFile, 0, NULL, FILE_END);	
	
	WriteFile(_hFile, _pExtraData, ulExtraDataSize, &BytesRW, NULL);
	
	// log : д������������
	return ERR_SUCCESS;
}