#include "shell.h"
#include "error.h"
#include "pe_utilities.h"


/*
	Description:	����shell����
*/
int ImployShell(void* _pImageBase)
{
	PIMAGE_NT_HEADERS pNTHeader = getNTHeader(_pImageBase);

	unsigned long shellsize = 0x1000;

	// TODO: ��ȡshell��Ҫ�Ĵ�С


	/*  ���������������ƶ�  */
	PIMAGE_SECTION_HEADER pLastSecHeader = getLastSecHeader(_pImageBase);
	for (int i = pNTHeader->FileHeader.NumberOfSections; i > 0; i--, pLastSecHeader--)
	{
			
	}

	return	ERR_SUCCESS;
}