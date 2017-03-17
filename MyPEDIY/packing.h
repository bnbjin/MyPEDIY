#ifndef __PACKING_H__
#define __PACKING_H__

#include "error.h"


#pragma pack(push)
#pragma pack(1)
struct PackInfoNode
{	
	void			*OriginalOffset;	// RVA
	unsigned long	OriginalSize;
	void			*PackedOffset;	// RVA
	unsigned long	PackedSize;
};
#pragma pack(pop)


/*
	Description :	ѹ���ļ�ӳ���е�����
*/
int PackFile(void *_pImageBase, void *_pMutateImp = 0, void *_pMutateReloc = 0, void *_pMutateTLS = 0);


/*
	Description:	����aplibѹ������ѹ������
*/
int PackData(PackInfoNode *_pPIN);


#endif // __PACKING_H__
