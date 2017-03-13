#include "import.h"
#include "error.h"

/*
	Description:	输入表变异处理
*/
int MutateImport()
{
#ifdef __IMPORT_SWITCH__
	//为简单，此处申请0xa0000内存存放新输入表（假设生成的新输入表结构尺寸小于0xa0000）
	m_pImportTable = new char[0xa0000];
	if (m_pImportTable == NULL)
	{
		AddLine(hDlg, "内存不足.");
		return FALSE;
	}
	ZeroMemory(m_pImportTable, 0xa0000);
	m_pImportTableSize = MoveImpTable(m_pImportTable);

	if (m_pImportTableSize == FALSE) {
		AddLine(hDlg, "处理输入表时指定的内存不足或程序没输入表.");
		return FALSE;
	}

	ClsImpTable();
	AddLine(hDlg, "输入表加密完成.");
#endif // __IMPORT_SWITCH__
	
	return ERR_SUCCESS;
}