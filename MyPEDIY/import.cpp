#include "import.h"
#include "error.h"

/*
	Description:	�������촦��
*/
int MutateImport()
{
#ifdef __IMPORT_SWITCH__
	//Ϊ�򵥣��˴�����0xa0000�ڴ�����������������ɵ��������ṹ�ߴ�С��0xa0000��
	m_pImportTable = new char[0xa0000];
	if (m_pImportTable == NULL)
	{
		AddLine(hDlg, "�ڴ治��.");
		return FALSE;
	}
	ZeroMemory(m_pImportTable, 0xa0000);
	m_pImportTableSize = MoveImpTable(m_pImportTable);

	if (m_pImportTableSize == FALSE) {
		AddLine(hDlg, "���������ʱָ�����ڴ治������û�����.");
		return FALSE;
	}

	ClsImpTable();
	AddLine(hDlg, "�����������.");
#endif // __IMPORT_SWITCH__
	
	return ERR_SUCCESS;
}