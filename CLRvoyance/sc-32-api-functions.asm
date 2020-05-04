; Shellcode functions to lookup API functions, based on The Shellcoder's Handbook http://eu.wiley.com/WileyCDA/WileyTitle/productCd-0764544683.html'
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2008/11/24: Refactored API functions to this include file


ARG0 equ 0x08
ARG1 equ 0x0C
ARG2 equ 0x10
ARG3 equ 0x14

; LookupFunctions(modulehash, number of functions, hashestables, functionstable)
LookupFunctions:
	push ebp
	mov ebp, esp
	push ecx
	push esi
	push edi
	mov ecx, [ebp+ARG1]
	mov esi, [ebp+ARG2]
	mov edi, [ebp+ARG3]
loopLookupFunctions:
	push dword [esi]
	push dword [ebp+ARG0]
	call GetFunctionAddress
	mov [edi], eax
	add edi, 0x04
	add esi, 0x04
	loop loopLookupFunctions
	pop edi
	pop esi
	pop ecx
	mov esp, ebp
	pop ebp
	ret 0x10

; GetFunctionAddress(modulehash, functionhash)
;  Return address of function with hash-value functionhash
GetFunctionAddress:
	push ebp
	mov ebp, esp
	push ebx
	push esi
	push edi
	push ecx
	push dword [fs:0x30]
	pop eax
	mov eax, [eax+0x0C]
	mov ecx, [eax+0x0C]
nextinlist:
	mov edx, [ecx]
	mov eax, [ecx+0x30]
	push 0x02
	mov edi, [ebp+ARG0]
	push edi
	push eax
	call HashIt
	test eax, eax
	jz foundmodule
	mov ecx, edx
	jmp nextinlist
foundmodule:
	mov eax, [ecx+0x18]
	push eax
	mov ebx, [eax+0x3c]
	add eax, ebx
	mov ebx, [eax+0x78]
	pop eax
	push eax
	add ebx, eax
	mov ecx, [ebx+0x1C]
	mov edx, [ebx+0x20]
	mov ebx, [ebx+0x24]
	add ecx, eax
	add edx, eax
	add ebx, eax
find_procedure:
	mov esi, [edx]
	pop eax
	push eax
	add esi, eax
	push 0x01
	push dword [ebp+ARG1]
	push esi
	call HashIt
	test eax, eax
	jz found_procedure
	add edx, 0x04
	add ebx, 0x02
	jmp find_procedure
found_procedure:
	pop eax
	xor edx, edx
	mov dx, [ebx]
	shl edx, 0x02
	add ecx, edx
	add eax, [ecx]
	pop ecx
	pop edi
	pop esi
	pop ebx
	mov esp, ebp
	pop ebp
	ret 0x08

; HashIt(string_address, hash, increment)
;  increment: 1 for ASCII, 2 for UNICODE
;  Return 0 if string at string_address has hash-value hash
;  Algorithm:
;    def HashIt(str):
;        hash = 0
;        for c in str:
;            hash = (hash + (ord(c) | 0x60)) << 1
;        return hash
HashIt:
	push ebp
	mov ebp, esp
	push ecx
	push ebx
	push edx
	xor ecx, ecx
	xor ebx, ebx
	xor edx, edx
	mov eax, [ebp+ARG0]
hashloop:
	mov dl, [eax]
	or dl, 0x60
	add ebx, edx
	shl ebx, 0x01
	add eax, [ebp+ARG2]
	mov cl, [eax]
	test cl, cl
	loopnz hashloop
	xor eax, eax
	mov ecx, [ebp+ARG1]
	cmp ebx, ecx
	jz donehash
	inc eax
donehash:
	pop edx
	pop ebx
	pop ecx
	mov esp, ebp
	pop ebp
	ret 0x0C

