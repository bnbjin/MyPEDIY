; x86

.586P
.MODEL FLAT,STDCALL
OPTION CASEMAP:NONE


INCLUDE c:\masm32\include\windows.inc
INCLUDE ASMshell.inc 


.code
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
	; �����������򲻿ɸı�
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
	; ��ȡ������ڵ� ebp = ��ڵ��ַ, Ϊ�����ṩѰַ����
	pop 	ebp
	sub		ebp, (Label_Induction_Import_Start - Label_Induction_Start)
	
	; *  ���´����Ǵ���DLLʱ������  *
	; ��DLL�ٴν���ʱ���ڶ���shell�Ѿ����ܣ���˿���ֱ�ӽ���
	mov		eax, dword ptr [ebp + (InductionData.nShellStep - Label_Induction_Start)]
	.if	eax != 0
		push	ebp
		jmp		dword ptr [ebp + (InductionData.LuanchAllocBase - Label_Induction_Start)]
	.endif
	inc		dword ptr [ebp + (InductionData.nShellStep - Label_Induction_Start)]	
	
	; ȡ��ǰӳ���ַ�������EXE�ں������Getmulehandleȡ��ַ��
	; todo: console��ȡ�����ַ
	mov		eax, dword ptr [esp + 24h]
	mov		dword ptr [ebp + (InductionData.PresentImageBase - Label_Induction_Start)], eax
	
	; *  ׼����ѹ���ڶ�����Ǵ���  *
	
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
	
	; VirtualAlloc(0, nLuanchPackSize, MEM_COMMIT, PAGE_READWRITE)
	push	PAGE_READWRITE
	push	MEM_COMMIT
	push	dword ptr [ebp + (InductionData.nLuanchPackSize - Label_Induction_Start)]
	push	0
	call	dword ptr [ebp + (InductionData.VirtualAllocAddr - Label_Induction_Start)]
	
	; ����ǵڶ��ε�ַ�ŵ�LuanchAllocBase��DLL�˳�ʱ���õ�
	push	eax ; ��Ӧ�����pop edx
	mov		dword ptr [ebp + (InductionData.LuanchAllocBase - Label_Induction_Start)], eax
	mov		ebx, dword ptr [ebp + (InductionData.LuanchBase - Label_Induction_Start)]
	
	; *  ��ѹ���ڶ�����Ǵ���  *
	; _aP_depack_asm(InductionBase + ebp, ǰ�������ڴ�ռ�);
IFNDEF __ASMSHELL_DEBUG__
	add		ebx, ebp
	push	eax
	push	ebx
	call	proc_aP_depack_asm
ENDIF	; IFDEF __ASMSHELL_DEBUG__
IFDEF __ASMSHELL_DEBUG__
	; *  ���Ƶڶ���SHELL��������ڴ�ռ���  *
	mov 	ecx, dword ptr [ebp + (InductionData.nLuanchPackSize - Label_Induction_Start)] 
	lea 	esi, dword ptr [ebp + (Label_Luanch_Start - Label_Shell_Start)]
	mov 	edi, eax
MoveLuanchToAllocation:
	mov 	al, byte ptr [esi]
	mov 	byte ptr [edi], al
	inc 	esi
	inc 	edi
	loop 	MoveLuanchToAllocation
ENDIF
	
	pop		edx	; ��Ӧ�����push eax
	; ����������ʼ�����ĵ�ַ���ڶ�����ǵ����ݱ���
	mov		ecx, 3h
	lea		esi, [ebp + (GPAAddr - Label_Induction_Start)]
	lea		edi, [edx + (LuanchData.GPAAddr - Label_Luanch_Start)]
MoveThreeFuncAddr:
	mov		eax, dword ptr [esi]
	mov		dword ptr [edi], eax
	add		esi,4h
	add		edi,4h
	loop	MoveThreeFuncAddr
	
	; ����ap_depack_asm��ַ���ڶ�����ǵ����ݱ���
	lea		eax, proc_aP_depack_asm
	mov		dword ptr [edx + (LuanchData.aPDepackASMAddr - Label_Luanch_Start)], eax
	
	; ����VirtualAlloc��ַ���ڶ�����ǵ����ݱ���
	mov		eax, dword ptr [ebp + (InductionData.VirtualAllocAddr - Label_Induction_Start)]	
	mov		dword ptr [edx + (LuanchData.VirtualAllocAddr - Label_Luanch_Start)], eax
	
	; ����PresentImageBase���ڶ�����ǵ����ݱ���
	mov 	eax, dword ptr [ebp + (InductionData.PresentImageBase - Label_Induction_Start)]
	mov 	dword ptr [edx + (LuanchData.PresentImageBase - Label_Luanch_Start)], eax
	
	; ��ת���ڶ���SHELL������
	push	ebp
	jmp		edx

Label_Induction_End LABEL DWORD


Label_Luanch_Start	LABEL	DWORD
	; need to popad
	
	; edx = Allocated Label_Luanch_Start VA
	call	$+5
	pop		edx
	sub		edx, 5h

	; ebp = Label_Induction_Start VA
	pop		ebp
	
	; �����DLL��������OEP
	mov		eax, dword ptr [edx + (InductionData.nShellStep - Label_Luanch_Start)]
	.if		eax != 0;dll�˳�ʱ���������OEP	
	        popad
	        jmp _Return_OEP
	.endif
	
	; �����EXE�ļ�������GetModuleHandle(NULL)��ȡӳ���е�ǰģ���ַ
	mov		eax, dword ptr [edx + (LuanchData.IsDll - Label_Luanch_Start)]
	.if		eax == 0
			push	0
			call	dword ptr [edx + (LuanchData.GMHAddr - Label_Luanch_Start)]
			mov		dword ptr [edx + (LuanchData.PresentImageBase - Label_Luanch_Start)], eax
	.endif

	; GetModuleHandle("kernel32.dll")
	; GetModuleHandle���޸�edx
	push 	edx
	lea		esi, dword ptr [edx + (LuanchData.szKer32DLLName - Label_Luanch_Start)]
	push	esi
	call	dword ptr [edx + (LuanchData.GMHAddr - Label_Luanch_Start)]
	pop		edx
	
	; ���kernel32.dll��δ���ص��ڴ��У���LoadLibrary("kernel32.dll")
	.if	eax == 0
		push edx
		push	esi
		call	dword ptr [edx + (LuanchData.LLAAddr - Label_Luanch_Start)]
		pop edx
	.endif


	; GetProcAddress(handle("kernel32.dll"), "VirtualFree")	
	; GetProcAddress���޸�edx
	push 	edx
	mov		esi, eax
	lea		ebx, dword ptr [edx + (LuanchData.szVirtualFree - Label_Luanch_Start)]
	push	ebx
	push	esi
	call	dword ptr [edx + (LuanchData.GPAAddr - Label_Luanch_Start)]
	pop 	edx
	mov		dword ptr [edx + (LuanchData.VirtualFreeADDR - Label_Luanch_Start)], eax
	
	
	; *  ��ѹ��������  *
	; *  �ָ�ԭ�����  *
	comment /
	push Label_Luanch_Start
	push edx
	proc_UnmutateImport
	/
	; *  �����ض�λ����  *
	; *  anti  dump  *
	
	
	; *  ��ʼ��ת��OEP  *
	; TODO: DLL���δ֪
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


; C calling convention
; size_t aP_depack_asm( const void *source, void *destination );
proc_aP_depack_asm PROC
    
	pushad
    mov    esi, [esp + 36]    
    mov    edi, [esp + 40]
    cld
    mov    dl, 80h
    xor    ebx, ebx
literal:
    movsb
    mov    bl, 2
nexttag:
    call   getbit
    jnc    literal

    xor    ecx, ecx
    call   getbit
    jnc    codepair
    xor    eax, eax
    call   getbit
    jnc    shortmatch
    mov    bl, 2
    inc    ecx
    mov    al, 10h
getmorebits:
    call   getbit
    adc    al, al
    jnc    getmorebits
    jnz    domatch
    stosb
    jmp    short nexttag
codepair:
    call   getgamma_no_ecx
    sub    ecx, ebx
    jnz    normalcodepair
    call   getgamma
    jmp    short domatch_lastpos
shortmatch:
    lodsb
    shr    eax, 1
    jz     donedepacking
    adc    ecx, ecx
    jmp    short domatch_with_2inc
normalcodepair:
    xchg   eax, ecx
    dec    eax
    shl    eax, 8
    lodsb
    call   getgamma
    cmp    eax, 32000
    jae    domatch_with_2inc
    cmp    ah, 5
    jae    domatch_with_inc
    cmp    eax, 7fh
    ja     domatch_new_lastpos
domatch_with_2inc:
    inc    ecx
domatch_with_inc:
    inc    ecx
domatch_new_lastpos:
    xchg   eax, ebp
domatch_lastpos:
    mov    eax, ebp
    mov    bl, 1
domatch:
    push   esi
    mov    esi, edi
    sub    esi, eax
    rep    movsb
    pop    esi
    jmp    short nexttag
getbit:
    add     dl, dl
    jnz     stillbitsleft
    mov     dl, [esi]
    inc     esi
    adc     dl, dl
stillbitsleft:
    ret
getgamma:
    xor    ecx, ecx
getgamma_no_ecx:
    inc    ecx
getgammaloop:
    call   getbit
    adc    ecx, ecx
    call   getbit
    jc     getgammaloop
    ret
donedepacking:
    sub    edi, [esp + 40]
    mov    [esp + 28], edi    ; return unpacked length in eax
    popad
    ret	8h
	
proc_aP_depack_asm ENDP


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