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
	; �����������򲻿ɸı�
	GPAAddr	MY_IMAGE_IMPORT_THUNK	<<GPAThunk - Label_Shell_Start>>	; GetProcAddress Address
	GMHAddr	MY_IMAGE_IMPORT_THUNK	<<GMHThunk - Label_Shell_Start>>	; GetModuleHandle Address
	LLAAddr	MY_IMAGE_IMPORT_THUNK	<<LLAThunk - Label_Shell_Start>>	; LoadLibraryA Address
			MY_IMAGE_IMPORT_THUNK	<<0>>

	; DLLName
	DLLName	DB	'KERNEL32.dll', 0, 0
	
	; Thunks
	GPAThunk	MY_IMAGE_IMPORT_BY_NAME	<0, 'GetProcAddress'>
	GMHThunk	MY_IMAGE_IMPORT_BY_NAME	<0, 'GetModuleHandleA'>
	LLAThunk	MY_IMAGE_IMPORT_BY_NAME	<0, 'LoadLibraryA'>

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
	
	; VirtualAlloc(0, nLuanchOriginalSize, MEM_COMMIT, PAGE_READWRITE)
	push	PAGE_READWRITE
	push	MEM_COMMIT
	push	dword ptr [ebp + (InductionData.nLuanchOriginalSize - Label_Induction_Start)]
	push	0
	call	dword ptr [ebp + (InductionData.VirtualAllocAddr - Label_Induction_Start)]
	
	; ����ǵڶ��ε�ַ�ŵ�LuanchAllocBase��DLL�˳�ʱ���õ�
	push	eax ; ��Ӧ�����pop edx
	mov		dword ptr [ebp + (InductionData.LuanchAllocBase - Label_Induction_Start)], eax
	
	; *  ��ѹ���ڶ�����Ǵ���  *
	
	; Proc_aP_depack_asm_safe(
	;			InductionBase + ebp, 
	;			InductionData.nLuanchPackSize
	;			ǰ�������ڴ�ռ�, 
	;			InductionData.nLuanchOriginalSize);
	push 	dword ptr [ebp + (InductionData.nLuanchOriginalSize - Label_Induction_Start)] 
	push	eax
	push 	dword ptr [ebp + (InductionData.nLuanchPackSize - Label_Induction_Start)]
	mov		ebx, dword ptr [ebp + (InductionData.LuanchBase - Label_Induction_Start)]
	add		ebx, ebp
	push	ebx
	call	Proc_aP_depack_asm_safe
	add		esp, 10h
	
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
	lea		eax, Proc_aP_depack_asm_safe
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
Proc_aP_depack_asm_safe PROC

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
	
Proc_aP_depack_asm_safe ENDP
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
		push	edx
		push	esi
		call	dword ptr [edx + (LuanchData.LLAAddr - Label_Luanch_Start)]
		pop		edx
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
	mov 	eax, DWORD PTR [edx + (LuanchData.IsMutateImpTable - Label_Luanch_Start)]
	.IF eax == 0
		push	DWORD PTR [edx + (LuanchData.LLAAddr - Label_Luanch_Start)]
		push	DWORD PTR [edx + (LuanchData.GMHAddr - Label_Luanch_Start)]
		push	DWORD PTR [edx + (LuanchData.GPAAddr - Label_Luanch_Start)]
		push	DWORD PTR [edx + (LuanchData.OriginalImpTableAddr - Label_Luanch_Start)]
		push	DWORD PTR [edx + (LuanchData.PresentImageBase - Label_Luanch_Start)]
		call	Proc_InitOrigianlImport
		add		esp, 14h
	.ELSE
		comment /
			push Label_Luanch_Start
			push edx
			Proc_UnmutateImport
		/
	.ENDIF
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


comment /
	Description:	
	Parameters:	RuntimeImageBase		DWORD
				OriginalImportRVA		DWORD	RVA to Imagebase
				MutateImportRVA			DWORD	RVA to ImageBase
/
comment /
Proc_UnmutateImport	PROC
	 
	pushad	;esp -= 0x20
	
	; ebp = RuntimeLuanchBase
	; esi = OriginalImportRVA
	; edi = MutateImportRVA
	mov		ebp, dword ptr ss:[esp + 24h]
	mov		esi, dword ptr ss:[esp + 28h]
	mov		edi, dword ptr ss:[esp + 2Ch]

	.WHILE	eax != 0
	
	.ENDW	
	
	popad
	ret 
	
Proc_UnmutateImport ENDP
/

ORDINAL_FLAG_DWORD	EQU	80000000h	
comment /
	Description:	��ʼ��ԭ�����
					C convention
	Parameters:		_RuntimeImageBase	DWORD
					_OriginalImportRVA	DWORD	RVA to ImageBase
					_GPAAddr			DWORD	
					_GMHAddr			DWORD
					_LLAAddr			DWORD
/
Proc_InitOrigianlImport PROC C PRIVATE \
	USES ebx edx esi edi \
	, _RuntimeImageBase:DWORD, _OriginalImportRVA:DWORD, _GPAAddr:DWORD, _GMHAddr:DWORD, _LLAAddr:DWORD
	
	mov 	edx, _RuntimeImageBase
	mov 	esi, _OriginalImportRVA
	
	mov 	eax, (MY_IMAGE_IMPORT_DESCRIPTOR PTR [edx + esi]).FirstThunk
	.WHILE  eax != 0
		mov 	edi, (MY_IMAGE_IMPORT_DESCRIPTOR PTR [edx + esi]).FirstThunk
		mov 	eax, DWORD PTR [edx + edi]
		.WHILE	eax != 0		
			; eax = GetModuleHandleA(Import.DLLName)
			; if (eax == 0)	LoadLibraryA(Import.DLLName)
			push	edx 
			mov 	eax, (MY_IMAGE_IMPORT_DESCRIPTOR PTR [edx + esi]).DLLName
			add 	eax, edx
			push 	eax
			call    DWORD PTR [_GMHAddr]
			pop		edx
			.IF eax == 0
				push 	edx
				mov 	eax, (MY_IMAGE_IMPORT_DESCRIPTOR PTR [edx + esi]).DLLName
				add 	eax, edx 
				push 	eax
				call 	DWORD PTR [_LLAAddr]
				pop		edx
			.ENDIF
			
			push	edx
			mov 	ebx, DWORD PTR [edx + edi]
			push 	ebx
			and		ebx, ORDINAL_FLAG_DWORD
			.IF		ebx == 0
			;	STRING
				pop 	ebx
				; GetProcAddress(eax, Import.FirstThunk[n])
				lea		ebx, DWORD PTR [edx + ebx + TYPE WORD]	;Խ��Hint
			.ELSE
			;	ORDINAL
				pop		ebx
				and		ebx, 0000ffffh
			.ENDIF
			push 	ebx
			push	eax
			call	DWORD PTR [_GPAAddr]
			pop		edx
			; Import.FirstThunk[n] = eax
			mov		DWORD PTR [edx + edi], eax
			
			; ����ָ��ָ����һ��IMPORT_THUNK_DATA
			add 	edi, TYPE DWORD
			mov		eax, DWORD PTR [edx + edi]
		.ENDW
		add 	esi, TYPE MY_IMAGE_IMPORT_DESCRIPTOR; ����ָ��ָ����һ��IMPORT_DESCRIPTOR
		mov		eax, (MY_IMAGE_IMPORT_DESCRIPTOR PTR [edx + esi]).FirstThunk
	.ENDW
	
	ret
	
Proc_InitOrigianlImport ENDP
 

Label_Luanch_End	LABEL 	DWORD
Label_Shell_End	LABEL	DWORD


END