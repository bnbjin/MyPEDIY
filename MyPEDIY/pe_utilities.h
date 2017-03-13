#ifndef __PE_UTILITIES_H__
#define __PE_UTILITIES_H__

#include <windows.h>

/*
	Description:	ȡ�����뺯��
*/
UINT AlignSize(UINT nSize, UINT nAlign);


/*
	Description:	RVA->ָ����ж�Ӧλ�õ�ָ��
*/
char* RVAToPtr(const void* imagebase, const unsigned long dwRVA);


/*
	Description:	��ȡNTͷָ��
*/
PIMAGE_NT_HEADERS getNTHeader(const void* imagebase);


/*
	Description:	��ȡsection��ָ��
*/
PIMAGE_SECTION_HEADER getSecHeader(const void* _imagebase);


/*
	Description:	��ȡ���һ���������ָ��
*/
PIMAGE_SECTION_HEADER getLastSecHeader(const void* _pImageBase);


/*
	Description:	������ȥ��β�����õ����ֽڣ����¼�������Ĵ�С
*/
unsigned int CalcMinSizeOfData(char* pSectionData, const unsigned int nSectionSize);


/*
	Description:	�жϵ�ǰ���������ܷ�ѹ��
*/
bool IsSectionPackable(PIMAGE_SECTION_HEADER pSecHeader);


/*
	Description:	�����ļ�
*/
int BackUpFile(TCHAR *szFilePath);


/*
	Description:	��ȡDOSͷ��С
*/
unsigned int GetDosHeaderSize(void* _pImageBase);


/*
	Description:	��ȡNTͷ��С
*/
unsigned int GetNTHeaderSize(void* _pImageBase);


#endif //__PE_UTILITIES_H__
