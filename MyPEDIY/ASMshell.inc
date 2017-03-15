IFNDEF __ASMSHELL_INC__
__ASMSHELL_INC__	equ	<1>
__ASMSHELL_DEBUG__	equ <1>

PUBLIC  C   Label_Shell_Start
PUBLIC  C   Label_Shell_End
PUBLIC	C	Label_Induction_Start
PUBLIC	C	Label_Induction_End
PUBLIC	C	Label_Induction_Data_Start
PUBLIC  C   Label_Induction_Data_End
PUBLIC  C 	Label_Mutate_Import_Start
PUBLIC  C 	Label_Mutate_Import_End
PUBLIC	C	Label_Luanch_Start
PUBLIC	C	Label_Luanch_End
PUBLIC	C	Lable_Luanch_Data_Start
PUBLIC 	C 	Lable_Luanch_Data_End
;PUBLIC	C	TlsTable
;PUBLIC	C	RelocBaseBegin


MY_IMAGE_IMPORT_DESCRIPTOR STRUCT    
	
	UNION Misc
		Characteristics 	DD	?	; 0 for terminating null import descriptor
		OriginalFirstThunk 	DD	?	; RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	ENDS
	
	TimeDateStamp	DD	?
	
    ForwarderChain	DD	?
    
	DLLName			DD	?
    
	FirstThunk		DD	?            ; RVA to IAT
	
MY_IMAGE_IMPORT_DESCRIPTOR ENDS


MY_IMAGE_IMPORT_THUNK STRUCT
	Hint		DW	?
	FuncName	DB	32 DUP (?)
MY_IMAGE_IMPORT_THUNK ENDS


INDUCTION_DATA STRUCT
	
	nShellStep	 		DD	0	; DLL可能会多次进入shell,通过统计进入步数来判断是EXE还是DLL
	
	LuanchBase	 		DD	?	; 需要外壳程序写入
	
	LuanchAllocBase	 	DD	?
	
	PresentImageBase	DD	?
	
	nLuanchPackSize		DD	?	; 需要外壳程序写入
	
	szVirtualAlloc	 	DB	'VirtualAlloc', 0
	
	VirtualAllocAddr 	DD	0
	
	TlsTable	 		DB	18h DUP (?)	; 暂时未使用到

INDUCTION_DATA ENDS


LUANCH_DATA STRUCT
OEP					DD	?	; 需要外壳程序写入
IsMutateImpTable	DD	?	; 需要外壳程序写入
OriginalImpTableAddr	DD	?	; 需要外壳程序写入
IsDll				DD	?	; 需要外壳程序写入
OriginalRelocAddr	DD	?	; 需要外壳程序写入	
SectionPackInfo		DB	0a0h DUP (?)	; 需要外壳程序写入
nLuanchAllocStep    DD	0
szVirtualFree		DB	'VirtualFree', 0
VirtualFreeADDR		DD	0
szKer32DLLName		DB	'KERNEL32.dll', 0, 0
hFile				DD	0
; 已下数据需要从第一段SHELL复制到第二段SHELL
; 三个函数次序不可改变
GPAAddr				DD	0
GMHAddr				DD	0
LLAAddr				DD	0
VirtualAllocAddr	DD	0
aPDepackASMAddr		DD	0
PresentImageBase	DD	0
LUANCH_DATA ENDS


; C calling convention
; size_t aP_depack_asm( const void *source, void *destination )；；
proc_aP_depack_asm PROTO


ENDIF  ; __ASMSHELL_INC__