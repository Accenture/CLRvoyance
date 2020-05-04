; x64 shellcode functions to lookup API functions, translated from and based on
; shellcode from McDermott Cybersecurity http://mcdermottcybersecurity.com
; This shellcode from McDermott is released under MIT license.
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2011/12/27: Refactored API functions to this include file
;	
; bja changes: 
;	- wrong_func with loop instruction had an off-by-one, preventing one from fetching the address
;	  of the first (hint 0) export of a DLL
;   - function search will return the wrong one for matching exports. For example, if you're looking for
;     MyCreate and the DLL exports MyCreateFunc before MyCreate, it'll return the address of MyCreateFunc
;     since it only checks if they match  
; 

REGISTERSIZE		equ 0x08
VARIABLESTRSIZE	equ 0x100

REGISTERINDEX_RBX equ 0 * REGISTERSIZE + STACKSPACE
REGISTERINDEX_RBP equ 1 * REGISTERSIZE + STACKSPACE
REGISTERINDEX_RDI equ 2 * REGISTERSIZE + STACKSPACE
REGISTERINDEX_RSI equ 3 * REGISTERSIZE + STACKSPACE
REGISTERINDEX_R12 equ 4 * REGISTERSIZE + STACKSPACE
REGISTERINDEX_R13 equ 5 * REGISTERSIZE + STACKSPACE
REGISTERINDEX_R14 equ 6 * REGISTERSIZE + STACKSPACE
REGISTERINDEX_R15 equ 7 * REGISTERSIZE + STACKSPACE
REGISTERCOUNT equ 8 ; must be even

VARIABLEINDEX_STR equ 8 * REGISTERSIZE + STACKSPACE

;look up address of function from DLL export table
;rcx=DLL name string, rdx=function name string, r8 address to store address function
;DLL name must be in uppercase
;r9=address of LoadLibraryA (optional, needed if export is forwarded)
;returns address in rax
;returns 0 if DLL not loaded or exported function not found in DLL
lookup_api:
	sub rsp, STACKSPACE + VARIABLESTRSIZE + REGISTERCOUNT * REGISTERSIZE		;set up stack frame in case we call loadlibrary
	mov [rsp + REGISTERINDEX_RBX], rbx		;save non-volatile registers
	mov [rsp + REGISTERINDEX_RBP], rbp
	mov [rsp + REGISTERINDEX_RDI], rdi
	mov [rsp + REGISTERINDEX_RSI], rsi
	mov [rsp + REGISTERINDEX_R12], r12
	mov [rsp + REGISTERINDEX_R13], r13
	mov [rsp + REGISTERINDEX_R14], r14
	mov [rsp + REGISTERINDEX_R15], r15

start:
	mov r11, [gs:0x60]								;peb
	mov r11, [r11 + 0x18]							;peb loader data
	lea r11, [r11 + 0x10]							;InLoadOrderModuleList (list head)
	mov r15, r11									;save for later
	mov r11, [r11]									;follow _LIST_ENTRY->Flink to first item in list
	cld

for_each_dll:										;r11 points to current _ldr_data_table_entry
	mov rdi, [r11 + 0x58 + 0x08]					;UNICODE_STRING at 58h, actual string buffer at 60h
	mov rsi, rcx									;pointer to dll we're looking for

compare_dll:
	lodsb											;load character of our dll name string
	test al, al										;check for null terminator
	jz found_dll									;if at the end of our string and all matched so far, found it

	mov ah, [rdi]									;get character of current dll
	cmp ah, 'a'										;lowercase 'a'
	jl uppercase
	sub ah, ' '										;convert to uppercase

uppercase:
	cmp ah, al
	jne wrong_dll									;found a character mismatch - try next dll

	inc rdi											;skip to next unicode character
	inc rdi
	jmp compare_dll									;continue string comparison

wrong_dll:
	mov r11, [r11]									;move to next _list_entry (following Flink pointer)
	cmp r11, r15									;see if we're back at the list head (circular list)
	jne for_each_dll

	xor rax, rax									;DLL not found
	jmp return

found_dll:
	mov rbx, [r11 + 0x30]							;get dll base addr - points to DOS "MZ" header

	mov r12d, [rbx + 0x3c]							;get DOS header e_lfanew field for offset to "PE" header
	add r12, rbx									;add to base - now r12 points to _image_nt_headers64
	add r12, 0x18 + 0x70							;18h to optional header + 70h to data directories
													;r12 now points to _image_data_directory[0] array entry
													;which is the export directory

	mov r13d, [r12]									;get virtual address of export directory
	test r13, r13									;if zero, module does not have export table
	jnz has_exports

	xor rax, rax									;no exports - function will not be found in dll
	jmp return

has_exports:
	lea r11, [rbx + r13]							;add dll base to get actual memory address
													;r11 points to _image_export_directory structure (see winnt.h)

	mov r14d, [r12 + 0x04]							; get size of export directory
	add r14, r13									;add base rva of export directory
													;r13 and r14 now contain range of export directory
													;will be used later to check if export is forwarded

	mov ecx, [r11 + 0x18]							;NumberOfNames
	mov r10d, [r11 + 0x20]							;AddressOfNames (array of RVAs)
	add r10, rbx									;add dll base
	
for_each_func:
	dec ecx											;point to last element in array (searching backwards)
	lea r12, [r10 + 4 * rcx]						;get current index in names array

	mov edi, [r12]									;get RVA of name
	add rdi, rbx									;add base
	mov rsi, rdx									;pointer to function we're looking for

compare_func:
	cmpsb
	jne wrong_func									;function name doesn't match

	mov al, [rsi]									;current character of our function
	test al, al										;check for null terminator
	jz potential_match								;if at the end of our string and all matched so far, we MIGHT have found it

	jmp compare_func								;continue string comparison

potential_match:
	mov al, [rdi]									;current character of DLL function
	test al, al 									;check for null terminator
	jz found_func									

	jmp compare_func

wrong_func:
	test ecx,ecx
	jnz for_each_func

	xor rax, rax									;function not found in export table
	jmp return

found_func:											;ecx is array index where function name found

													;r11 points to _image_export_directory structure
	mov r12d, [r11 + 0x24]							; AddressOfNameOrdinals (rva)
	add r12, rbx									;add dll base address
	mov cx, [r12 + 2 * rcx]							;get ordinal value from array of words

	mov r12d, [r11 + 0x1c]							;AddressOfFunctions (rva)
	add r12, rbx									;add dll base address
	mov eax, [r12 + 4 * rcx]						;Get RVA of function using index

	cmp rax, r13									;see if func rva falls within range of export dir
	jl not_forwarded
	cmp rax, r14									;if r13 <= func < r14 then forwarded
	jae not_forwarded

	;forwarded function address points to a string of the form <DLL name>.<function>
	;note: dll name will be in uppercase
	;extract the DLL name and add ".DLL"

	lea rsi, [rax + rbx]							;add base address to rva to get forwarded function name
	lea rdi, [rsp + VARIABLEINDEX_STR]		;using STR space on stack as a work area

copy_dll_name:
	movsb
	cmp byte [rsi], '.'								;check for '.' (period) character
	jne copy_dll_name

	movsb											;also copy period
	mov dword [rdi], "DLL"							;0x004c4c44	add "DLL" extension and null terminator

	mov r14, r8										;save r8
	lea rcx, [rsp + VARIABLEINDEX_STR]				;points to "<DLL name>.DLL" string on stack
	call r9											;call LoadLibraryA with target dll
	mov r8, r14										;restore r8

	lea rcx, [rsp + VARIABLEINDEX_STR]				;target dll name
	mov rdx, rsi									;target function name
	jmp start										;start over with new parameters

not_forwarded:
	add rax, rbx									;add base addr to rva to get function address
return:
	mov [r8], rax									;store function address in variable

	mov rbx, [rsp + REGISTERINDEX_RBX]		;restore non-volatile registers
	mov rbp, [rsp + REGISTERINDEX_RBP]
	mov rdi, [rsp + REGISTERINDEX_RDI]
	mov rsi, [rsp + REGISTERINDEX_RSI]
	mov r12, [rsp + REGISTERINDEX_R12]
	mov r13, [rsp + REGISTERINDEX_R13]
	mov r14, [rsp + REGISTERINDEX_R14]
	mov r15, [rsp + REGISTERINDEX_R15]
	add rsp, STACKSPACE + VARIABLESTRSIZE + REGISTERCOUNT * REGISTERSIZE		;clean up stack
	ret
