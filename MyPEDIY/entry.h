#ifndef __ENTRY_H__
#define __ENTRY_H__

#include <windows.h>


/*
	Description:	�����Ӵ��ڻص�����
*/
INT_PTR CALLBACK SubCTLDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam);


/*
	Description:	���Կ����Ӵ��ڹ���
*/
INT_PTR CALLBACK SubSWTDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam);


/*
	Description:	���ڳ��򴰿�
*/
INT_PTR CALLBACK AboutPGMDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam);


/*
	Description:	�������ߴ���
*/
INT_PTR CALLBACK AboutAuthorDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam);


/*
	Description:	���Ի�����Ϣ�ص�����
*/
INT_PTR CALLBACK MainDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam);


#endif // __ENTRY_H__