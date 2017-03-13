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
		Description :	压缩文件处理
*/
int PackFile(HANDLE hFile, const void* imagebase);


/*
	Description:	调用aplib压缩引擎压缩数据
*/
bool PackData(
	const char* psrc,
	const unsigned long srcsize,
	char* pdes,
	unsigned long *dessize);


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
	unsigned long nPackSize);


#endif // __PACKING_H__
