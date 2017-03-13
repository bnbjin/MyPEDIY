#ifndef __PEDIY_H__
#define __PEDIY_H__

#include <windows.h>


/*
	Description:	������������
	RetValue:		ERR_SUCCESS
					ERR_UNKNOWN
*/
int ProtTheFile(TCHAR *szFilePath);


/*
	Description:	�ж��ļ��Ƿ�Ϊ��ЧPE�ļ�
	RetValue:		ERR_INVALIDFILE
					ERR_SUCCESS
*/
int IsPEFile(TCHAR *szFilePath);


/*
	Description:	��ȡĿ���ļ������У�����Ӱ��ʽ
	Parameters:		TCHAR *szFilePath	in:�ļ�·��
	HANDLE *hFile		out:
	void **imagebase	out:
*/
int ReadFileToHeap(TCHAR *szFilePath, HANDLE *_hfile, void **_pimagebase);


/*
	Description:	�����ݴӶ�д�뵽�ļ�
*/
int WriteHeapToFile(HANDLE _hFile, void* _pImageBase);


/*
	Description:	����PEͷ��Ϣ
*/
int FixPEHeader(void *_pimagebase);

#endif // __PEDIY_H__
