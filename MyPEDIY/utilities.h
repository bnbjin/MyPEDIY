#ifndef __UTILITIES_H__
#define __UTILITIES_H__

#include <windows.h>

/*
	Description: �򿪶Ի�����
*/
BOOL  OpenFileDlg(TCHAR *szFilePath, HWND hwnd);

/*
	Description:	����Ϣ��������һ����Ϣ���
*/
void AddLine(HWND hDlg, TCHAR *szMsg);

#endif // __UTILITIES_H__
