; x86

.586P
.MODEL FLAT,STDCALL
OPTION CASEMAP:NONE


INCLUDE c:\masm32\include\windows.inc
INCLUDE ASMshell.inc 


.CODE
Label_Shell_Start	LABEL	DWORD
Label_Induction_Start	LABEL	DWORD

_EntryPoint:
	pushad
	call __next0

Label_Induction_Import_Start 	LABEL	DWORD
	
	ImportTable		MY_IMAGE_IMPORT_DESCRIPTOR <<GPAAddr - Label_Shell_Start>, 0, 0, (DLLName - Label_Shell_Start), (GPAAddr - Label_Shell_Start)>
	DumbDescriptor	MY_IMAGE_IMPORT_DESCRIPTOR <<0>, 0, 0, 0, 0>       

Label_Induction_Import_End	LABEL	DWORD	
	
	; IAT
	; 三个函数次序不可改变
	GPAAddr	DD	GPAThunk - Label_Shell_Start	; GetProcAddress Address
	GMHAddr	DD	GMHThunk - Label_Shell_Start	; GetModuleHandle Address
	LLAAddr	DD	LLAThunk - Label_Shell_Start	; LoadLibraryA Address
			DD  0

	; DLLName
	DLLName	DB	'KERNEL32.dll', 0, 0
	
	; Thunks
	GPAThunk	MY_IMAGE_IMPORT_THUNK	<0, 'GetProcAddress'>
	GMHThunk	MY_IMAGE_IMPORT_THUNK	<0, 'GetModuleHandleA'>
	LLAThunk	MY_IMAGE_IMPORT_THUNK	<0, 'LoadLibraryA'>

	; todo: mutate reloc data
Label_Induction_Data_Start	LABEL	DWORD
	InductionData INDUCTION_DATA <>
Label_Induction_Data_End	LABEL	DWORD

__next0:	
	; 获取程序入口点 ebp = 入口点地址, 为后面提供寻址作用
	pop 	ebp
	sub		ebp, (Label_Induction_Import_Start - Label_Induction_Start)
	
	; *  以下代码是处理DLL时起作用  *
	; 当DLL再次进入时，第二段shell已经解密，因此可以直接进入
	mov		eax, dword ptr [ebp + (InductionData.nShellStep - Label_Induction_Start)]
	.if	eax != 0
		push	ebp
		jmp		dword ptr [ebp + (InductionData.LuanchAllocBase - Label_Induction_Start)]
	.endif
	inc		dword ptr [ebp + (InductionData.nShellStep - Label_Induction_Start)]	
	
	; 取当前映像基址，如果是EXE在后面会用Getmulehandle取基址的
	; todo: console获取错误地址
	mov		eax, dword ptr [esp + 24h]
	mov		dword ptr [ebp + (InductionData.PresentImageBase - Label_Induction_Start)], eax
	
	; *  准备解压缩第二段外壳代码  *
	
	; GetModuleHandle(DLLName)
	lea		esi, [ebp + (DLLName - Label_Induction_Start)]
	push	esi
	call	dword ptr [ebp + (GMHAddr - Label_Induction_Start)]
	
	; GetProcAddress(handle(DLLName),"VirtualAlloc")
	lea		esi, [ebp + (InductionData.szVirtualAlloc - Label_Induction_Start)]
	push	esi
	push	eax
	call	dword ptr [ebp + (GPAAddr - Label_Induction_Start)]
	mov		dword ptr [ebp + (InductionData.VirtualAllocAddr - Label_Induction_Start)],eax
	
	; VirtualAlloc(0, nLuanchOriginalSize, MEM_COMMIT, PAGE_READWRITE)
	push	PAGE_READWRITE
	push	MEM_COMMIT
	push	dword ptr [ebp + (InductionData.nLuanchOriginalSize - Label_Induction_Start)]
	push	0
	call	dword ptr [ebp + (InductionData.VirtualAllocAddr - Label_Induction_Start)]
	
	; 将外壳第二段地址放到LuanchAllocBase，DLL退出时会用到
	push	eax ; 对应下面的pop edx
	mov		dword ptr [ebp + (InductionData.LuanchAllocBase - Label_Induction_Start)], eax
	
	; *  解压缩第二段外壳代码  *
	
	; proc_aP_depack_asm_safe(
	;			InductionBase + ebp, 
	;			InductionData.nLuanchPackSize
	;			前面分配的内存空间, 
	;			InductionData.nLuanchOriginalSize);
	push 	dword ptr [ebp + (InductionData.nLuanchOriginalSize - Label_Induction_Start)] 
	push	eax
	push 	dword ptr [ebp + (InductionData.nLuanchPackSize - Label_Induction_Start)]
	mov		ebx, dword ptr [ebp + (InductionData.LuanchBase - Label_Induction_Start)]
	add		ebx, ebp
	push	ebx
	call	proc_aP_depack_asm_safe
	add		esp, 10h
	
	pop		edx	; 对应上面的push eax
	; 复制三个初始函数的地址到第二段外壳的数据表中
	mov		ecx, 3h
	lea		esi, [ebp + (GPAAddr - Label_Induction_Start)]
	lea		edi, [edx + (LuanchData.GPAAddr - Label_Luanch_Start)]
MoveThreeFuncAddr:
	mov		eax, dword ptr [esi]
	mov		dword ptr [edi], eax
	add		esi,4h
	add		edi,4h
	loop	MoveThreeFuncAddr
	
	; 复制ap_depack_asm地址到第二段外壳的数据表中
	lea		eax, proc_aP_depack_asm_safe
	mov		dword ptr [edx + (LuanchData.aPDepackASMAddr - Label_Luanch_Start)], eax
	
	; 复制VirtualAlloc地址到第二段外壳的数据表中
	mov		eax, dword ptr [ebp + (InductionData.VirtualAllocAddr - Label_Induction_Start)]	
	mov		dword ptr [edx + (LuanchData.VirtualAllocAddr - Label_Luanch_Start)], eax
	
	; 复制PresentImageBase到第二段外壳的数据表中
	mov 	eax, dword ptr [ebp + (InductionData.PresentImageBase - Label_Induction_Start)]
	mov 	dword ptr [edx + (LuanchData.PresentImageBase - Label_Luanch_Start)], eax
	
	; 跳转到第二段SHELL代码中
	push	ebp
	jmp		edx

Label__aP_depack_asm_safe_Start LABEL DWORD

; C calling convention
getbitM MACRO
LOCAL stillbitsleft
    add    dl, dl
    jnz    stillbitsleft

    sub    dword ptr [esp + 4], 1 ; read one byte from source
    jc     return_error           ;

    mov    dl, [esi]
    inc    esi

    add    dl, dl
    inc    dl
stillbitsleft:
ENDM getbitM

domatchM MACRO reg
    push   ecx
    mov    ecx, [esp + 60]    ; ecx = dstlen
    sub    ecx, [esp + 4]     ; ecx = num written
    cmp    reg, ecx
    pop    ecx
    ja     return_error

    sub    [esp], ecx         ; write ecx bytes to destination
    jc     return_error       ;

    push   esi
    mov    esi, edi
    sub    esi, reg
    rep    movsb
    pop    esi
ENDM domatchM

getgammaM MACRO reg
LOCAL getmorebits
    mov    reg, 1
getmorebits:
    getbitM
    adc    reg, reg
    jc     return_error
    getbitM
    jc     getmorebits
ENDM getgammaM

comment /
	Description:
		C convention
		unsigned int aP_depack_safe(const void *source,
                            unsigned int srclen,
                            void *destination,
                            unsigned int dstlen);
/
proc_aP_depack_asm_safe PROC

    pushad

    mov    esi, [esp + 36]    ; C calling convention
    mov    eax, [esp + 40]
    mov    edi, [esp + 44]
    mov    ecx, [esp + 48]

    push   eax
    push   ecx

    test   esi, esi
    jz     return_error

    test   edi, edi
    jz     return_error

    cld
    xor    edx, edx

literal:
    sub    dword ptr [esp + 4], 1 ; read one byte from source
    jc     return_error           ;

    mov    al, [esi]
    add    esi, 1

    sub    dword ptr [esp], 1 ; write one byte to destination
    jc     return_error       ;

    mov    [edi], al
    add    edi, 1

    mov    ebx, 2

nexttag:
    getbitM
    jnc    literal

    getbitM
    jnc    codepair

    xor    eax, eax
    getbitM
    jnc    shortmatch

    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    jz     thewrite

    mov    ebx, [esp + 56]    ; ebx = dstlen
    sub    ebx, [esp]         ; ebx = num written
    cmp    eax, ebx
    ja     return_error

    push   edi
    sub    edi, eax
    mov    al, [edi]
    pop    edi

thewrite:
    sub    dword ptr [esp], 1 ; write one byte to destination
    jc     return_error       ;

    mov    [edi], al
    inc    edi

    mov    ebx, 2

    jmp    nexttag

codepair:
    getgammaM eax

    sub    eax, ebx

    mov    ebx, 1

    jnz    normalcodepair

    getgammaM ecx

    domatchM ebp

    jmp    nexttag

normalcodepair:
    dec    eax

    test   eax, 0ff000000h
    jnz    return_error

    shl    eax, 8

    sub    dword ptr [esp + 4], 1 ; read one byte from source
    jc     return_error           ;

    mov    al, [esi]
    inc    esi

    mov    ebp, eax

    getgammaM ecx

    cmp    eax, 32000
    sbb    ecx, -1

    cmp    eax, 1280
    sbb    ecx, -1

    cmp    eax, 128
    adc    ecx, 0

    cmp    eax, 128
    adc    ecx, 0

    domatchM eax

    jmp    nexttag

shortmatch:
    sub    dword ptr [esp + 4], 1 ; read one byte from source
    jc     return_error           ;

    mov    al, [esi]
    inc    esi

    xor    ecx, ecx
    db     0c0h, 0e8h, 001h
    jz     donedepacking

    adc    ecx, 2

    mov    ebp, eax

    domatchM eax

    mov    ebx, 1

    jmp    nexttag

return_error:
    add    esp, 8

    popad

    or     eax, -1            ; return APLIB_ERROR in eax

    ret

donedepacking:
    add    esp, 8

    sub    edi, [esp + 40]
    mov    [esp + 28], edi    ; return unpacked length in eax

    popad

    ret
	
proc_aP_depack_asm_safe ENDP
Label__aP_depack_asm_safe_End LABEL DWORD
	
Label_Induction_End LABEL DWORD


Label_Luanch_Start	LABEL	DWORD
	; need to popad
	
	; edx = Allocated Label_Luanch_Start VA
	call	$+5
	pop		edx
	sub		edx, 5h

	; ebp = Label_Induction_Start VA
	pop		ebp
	
	; 如果是DLL，则跳到OEP
	mov		eax, dword ptr [edx + (InductionData.nShellStep - Label_Luanch_Start)]
	.if		eax != 0;dll退出时从这里进入OEP	
	        popad
	        jmp _Return_OEP
	.endif
	
	; 如果是EXE文件，则用GetModuleHandle(NULL)获取映射中当前模块基址
	mov		eax, dword ptr [edx + (LuanchData.IsDll - Label_Luanch_Start)]
	.if		eax == 0
			push	0
			call	dword ptr [edx + (LuanchData.GMHAddr - Label_Luanch_Start)]
			mov		dword ptr [edx + (LuanchData.PresentImageBase - Label_Luanch_Start)], eax
	.endif

	; GetModuleHandle("kernel32.dll")
	; GetModuleHandle会修改edx
	push 	edx
	lea		esi, dword ptr [edx + (LuanchData.szKer32DLLName - Label_Luanch_Start)]
	push	esi
	call	dword ptr [edx + (LuanchData.GMHAddr - Label_Luanch_Start)]
	pop		edx
	
	; 如果kernel32.dll尚未加载到内存中，则LoadLibrary("kernel32.dll")
	.if	eax == 0
		push edx
		push	esi
		call	dword ptr [edx + (LuanchData.LLAAddr - Label_Luanch_Start)]
		pop edx
	.endif


	; GetProcAddress(handle("kernel32.dll"), "VirtualFree")	
	; GetProcAddress会修改edx
	push 	edx
	mov		esi, eax
	lea		ebx, dword ptr [edx + (LuanchData.szVirtualFree - Label_Luanch_Start)]
	push	ebx
	push	esi
	call	dword ptr [edx + (LuanchData.GPAAddr - Label_Luanch_Start)]
	pop 	edx
	mov		dword ptr [edx + (LuanchData.VirtualFreeADDR - Label_Luanch_Start)], eax
	
	
	; *  解压缩各区块  *
	; *  恢复原输入表  *
	comment /
	push Label_Luanch_Start
	push edx
	proc_UnmutateImport
	/
	; *  修正重定位数据  *
	; *  anti  dump  *
	
	
	; *  开始跳转到OEP  *
	; TODO: DLL情况未知
	inc 	dword ptr [edx + (InductionData.nShellStep - Label_Luanch_Start)]
	mov		eax, dword ptr [edx + (LuanchData.OEP - Label_Luanch_Start)]
	add		eax, dword ptr [edx + (LuanchData.PresentImageBase - Label_Luanch_Start)]
	mov		dword ptr [edx + (_Return_OEP - Label_Luanch_Start)], eax
	popad
	DB		68h	; encode of push
_Return_OEP: 
	DD		0
	ret

Lable_Luanch_Data_Start	LABEL	DWORD

LuanchData	LUANCH_DATA	<>

Lable_Luanch_Data_End	LABEL 	DWORD

comment /
	Description:	
	Parameters:	RuntimeLuanchBase		DWORD
				CompiletimeLuanchBase	DWORD		
/
comment /
proc_UnmutateImport PROC 
	USES	ebp, eax, ebx, ecx, edx, esi, edi 
	; ebp = RuntimeLuanchBase
	mov	ebp, dword ptr ss:[esp + 4h]
	
AllSectionDePacked:
	mov	eax,dword ptr [ebp+(S_IsProtImpTable-ShellStart)]
	.if	eax == 0
		mov	edi,dword ptr [ebp+(ImpTableAddr-ShellStart)]
		add	edi,dword ptr [ebp+(FileHandle-ShellStart)]
	    GetNextDllFuncAddr:
		mov	esi,dword ptr [edi+0ch]
		.if	esi == 0
			jmp	AllDllFuncAddrGeted
		.endif
		add	esi,dword ptr [ebp+(FileHandle-ShellStart)]
		push	esi
		call	dword ptr [ebp+(GetmulehandleADDR-ShellStart)]
		.if	eax==0
			push	esi
			call	dword ptr [ebp+(LoadlibraryADDR-ShellStart)]
		.endif
		mov	esi,eax
		mov	edx,dword ptr [edi]
		.if	edx == 0
			mov	edx,dword ptr [edi+10h]
		.endif
		add	edx,dword ptr [ebp+(FileHandle-ShellStart)]
		mov	ebx,dword ptr [edi+10h]
		add	ebx,dword ptr [ebp+(FileHandle-ShellStart)]
	    GetNextFuncAddr:
		mov	eax,dword ptr [edx]
		.if	eax == 0
			jmp	AllFuncAddrGeted
		.endif
		push	ebx
		push	edx
		cdq
		.if	edx == 0	
			add	eax,2h
			add	eax,dword ptr [ebp+(FileHandle-ShellStart)]
		.else
			and	eax,7fffffffh
		.endif
		push	eax
		push	esi
		call	dword ptr [ebp+(GetprocaddressADDR-ShellStart)]
		mov	dword ptr [ebx],eax
		pop	edx
		pop	ebx
		add	edx,4h
		add	ebx,4h
		jmp	GetNextFuncAddr
AllFuncAddrGeted:
		add	edi,14h
		jmp	GetNextDllFuncAddr
	    AllDllFuncAddrGeted:
	.else
		mov	edx,dword ptr [ebp+(ImpTableAddr-ShellStart)]
		add	edx,ebp
	    GetNextDllFuncAddr2:
		mov	edi,dword ptr [edx]
		.if	edi == 0
			jmp	AllDllFuncAddrGeted2
		.endif
		add	edi,dword ptr [ebp+(FileHandle-ShellStart)]
		add	edx,5h
		mov	esi,edx
		push	esi
		call	dword ptr [ebp+(GetmulehandleADDR-ShellStart)]
		.if	eax==0
			push	esi
			call	dword ptr [ebp+(LoadlibraryADDR-ShellStart)]
		.endif
		movzx	ecx,byte ptr [esi-1]
		add	esi,ecx
		mov	edx,esi
		mov	esi,eax
		inc	edx
		mov	ecx,dword ptr [edx]
		add	edx,4h
	    GetNextFuncAddr2:
		push	ecx
		movzx	eax,byte ptr [edx]
		.if	eax == 0
			inc	edx
			push	edx
			mov	eax,dword ptr [edx]
			push	eax
			push	esi
			call	dword ptr [ebp+(GetprocaddressADDR-ShellStart)]
			mov	dword ptr [edi],eax
			pop	edx
			add	edx,4h
		.else
			inc	edx
			push	edx
			push	edx
			push	esi
			call	dword ptr [ebp+(GetprocaddressADDR-ShellStart)]
			mov	dword ptr [edi],eax
			pop	edx
			movzx	eax,byte ptr [edx-1]
			add	edx,eax
		.endif
		inc	edx
		add	edi,4h
		pop	ecx
		loop	GetNextFuncAddr2
		jmp	GetNextDllFuncAddr2
	    AllDllFuncAddrGeted2:
	.endif
	
	ret 4h
proc_UnMutateImport ENDP
/

Label_Luanch_End	LABEL 	DWORD
Label_Shell_End	LABEL	DWORD


END