%include "sc-64-macros.asm"

segment .text
	; setup environment, reserve stack space
	sub rsp, STACKSPACE + ROUND_EVEN(APIFUNCTIONCOUNT) * POINTERSIZE
	jmp execunet
	ret

%include "sc-64-api-functions.asm"
%include "sc-64-execunet.asm"

ASSEMBLY_LENGTH equ 1094795585
ASSEMBLY:
db 0x00