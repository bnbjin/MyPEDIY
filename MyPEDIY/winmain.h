#ifndef __WINMIAN_H__
#define __WINMIAN_H__

#include <windows.h>


/*
	Description:	控制子窗口回调函数
*/
INT_PTR CALLBACK SubCTLDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam);


/*
	Description:	属性开关子窗口过程
*/
INT_PTR CALLBACK SubSWTDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam);


/*
	Description:	关于程序窗口
*/
INT_PTR CALLBACK AboutPGMDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam);


/*
	Description:	关于作者窗口
*/
INT_PTR CALLBACK AboutAuthorDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam);


/*
	Description:	主对话框消息回调函数
*/
INT_PTR CALLBACK MainDlg(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam);


/*
	Description:	程序入口点
					1.启动主对话框
*/
int CALLBACK WinMain(
	_In_ HINSTANCE hInstance,
	_In_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nCmdShow);


#endif // __WINMIAN_H__