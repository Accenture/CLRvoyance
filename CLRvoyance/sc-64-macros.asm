; x64 shellcode macros to lookup API functions
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; Source code put in public domain by Didier Stevens, no Copyright
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2011/12/27: Refactored API functions to this include file

BITS 64

STACKSPACE	equ 0x28
POINTERSIZE	equ 0x08

;macro to round up number to the next even number
%define ROUND_EVEN(x) (x + x % 2)

%macro LOOKUP_API 3
	mov r8, %3
	lea rdx, [rel %2]
	lea rcx, [rel %1]
	call lookup_api
%endmacro

; lookup_api for RWX shellcode
%macro LOOKUP_API_RWX 3
	lea r8, [rsp + %3]
	lea rdx, [rel %2]
	lea rcx, [rel %1]
	call lookup_api
%endmacro

%macro LOOKUP_API 4
	mov r9, [rsp + %4]
	lea r8, [rsp + %3]
	lea rdx, [rel %2]
	lea rcx, [rel %1]
	call lookup_api
%endmacro