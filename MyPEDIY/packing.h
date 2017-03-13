#ifndef __PACKING_H__
#define __PACKING_H__

#include <list>
#include <windows.h>

typedef struct _PackInfoNode
{
	unsigned long originaloffset;	// RVA
	unsigned long originalsize;
	unsigned long packsize;
}PackInfoNode;

// extern std::list<PackInfoNode> PackInfoTable;


/*
		Description :	ѹ���ļ�����
*/
int PackFile(HANDLE hFile, const void* imagebase);


/*
	Description:	����aplibѹ������ѹ������
*/
bool PackData(
	const char* psrc,
	const unsigned long srcsize,
	char* pdes,
	unsigned long *dessize);


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
	unsigned long nPackSize);


#endif // __PACKING_H__
