#include "shell.h"
#include "error.h"
#include "pe_utilities.h"


/*
	Description:	安置shell区块
*/
int ImployShell(void* _pImageBase)
{
	PIMAGE_NT_HEADERS pNTHeader = getNTHeader(_pImageBase);

	unsigned long shellsize = 0x1000;

	// TODO: 获取shell需要的大小


	/*  把所有区块往后移动  */
	PIMAGE_SECTION_HEADER pLastSecHeader = getLastSecHeader(_pImageBase);
	for (int i = pNTHeader->FileHeader.NumberOfSections; i > 0; i--, pLastSecHeader--)
	{
			
	}

	return	ERR_SUCCESS;
}