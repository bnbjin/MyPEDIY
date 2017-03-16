#ifndef __WINMIAN_H__
#define __WINMIAN_H__

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
INT_PTR CALLBACK MainDlg(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam);


/*
	Description:	������ڵ�
					1.�������Ի���
*/
int CALLBACK WinMain(
	_In_ HINSTANCE hInstance,
	_In_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nCmdShow);


#endif // __WINMIAN_H__