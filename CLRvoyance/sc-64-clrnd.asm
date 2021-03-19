%include "sc-64-macros.asm"

%define APPDOMAIN_NAME "aXbpOzzF"

segment .text
	
	; setup environment, reserve stack space
	sub rsp, STACKSPACE + ROUND_EVEN(APIFUNCTIONCOUNT) * POINTERSIZE
	jmp execunet
	ret

%include "sc-64-api-functions.asm"
%include "sc-64-execunet.asm"

APPDOMAIN_VALUE:
	db __utf16__(APPDOMAIN_NAME), 0, 0

ASSEMBLY_LENGTH equ 1094795585
ASSEMBLY:
db 0x00