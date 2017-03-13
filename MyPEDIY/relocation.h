#ifndef __RELOCATION_H__
#define __RELOCATION_H__

#include <windows.h>

//�����ض�λ��ṹ
typedef struct _IMAGE_BASE_RELOCATION2 {
	DWORD   VirtualAddress;
	DWORD   SizeOfBlock;
	WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION2;

// typedef IMAGE_BASE_RELOCATION2 UNALIGNED * PIMAGE_BASE_RELOCATION2;
typedef IMAGE_BASE_RELOCATION2 *PIMAGE_BASE_RELOCATION2;

//�¹�����ض�λ��ṹ
/*	typedef struct _NEWIMAGE_BASE_RELOCATION {
BYTE   type;
DWORD  FirstTypeRVA;
BYTE   nNewItemOffset[1];
}
*/


/*
	Description:	�ض�λ����촦����
*/
bool MutateRelocation();

#endif // __RELOCATION_H__