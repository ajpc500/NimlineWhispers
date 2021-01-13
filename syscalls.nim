{.passC:"-masm=intel".}


proc GetTEBAsm64(): LPVOID {.asmNoStackFrame.} =
    asm """
	push rbx
    xor rbx, rbx
    xor rax, rax
    mov rbx, qword ptr gs:[0x30]
	mov rax, rbx
	pop rbx
	ret
    """

proc NtAdjustPrivilegesToken(TokenHandle: HANDLE, DisableAllPrivileges: BOOLEAN, NewState: PTOKEN_PRIVILEGES, BufferLength: ULONG, PreviousState: PTOKEN_PRIVILEGES, ReturnLength: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                                 
NtAdjustPrivilegesToken_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtAdjustPrivilegesToken_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtAdjustPrivilegesToken_Check_10_0_XXXX
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtAdjustPrivilegesToken_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtAdjustPrivilegesToken_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtAdjustPrivilegesToken_SystemCall_6_3_XXXX
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7601
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtAdjustPrivilegesToken_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtAdjustPrivilegesToken_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtAdjustPrivilegesToken_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19042
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_SystemCall_6_1_7600:          
	mov eax, 0x003e
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_1_7601:          
	mov eax, 0x003e
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_2_XXXX:          
	mov eax, 0x003f
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_3_XXXX:          
	mov eax, 0x0040
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_10240:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_10586:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_14393:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_15063:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_16299:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_17134:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_17763:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_18362:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_18363:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_19041:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_19042:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_Unknown:           
	ret
NtAdjustPrivilegesToken_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NtAllocateVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                                 
NtAllocateVirtualMemory_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtAllocateVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtAllocateVirtualMemory_Check_10_0_XXXX
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtAllocateVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtAllocateVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtAllocateVirtualMemory_SystemCall_6_3_XXXX
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtAllocateVirtualMemory_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtAllocateVirtualMemory_SystemCall_6_1_7601
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtAllocateVirtualMemory_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtAllocateVirtualMemory_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtAllocateVirtualMemory_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtAllocateVirtualMemory_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtAllocateVirtualMemory_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtAllocateVirtualMemory_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtAllocateVirtualMemory_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtAllocateVirtualMemory_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtAllocateVirtualMemory_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtAllocateVirtualMemory_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtAllocateVirtualMemory_SystemCall_10_0_19042
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_SystemCall_6_1_7600:          
	mov eax, 0x0015
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_6_1_7601:          
	mov eax, 0x0015
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_6_2_XXXX:          
	mov eax, 0x0016
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_6_3_XXXX:          
	mov eax, 0x0017
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_10240:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_10586:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_14393:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_15063:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_16299:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_17134:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_17763:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_18362:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_18363:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_19041:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_19042:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_Unknown:           
	ret
NtAllocateVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NtClose(Handle: HANDLE): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                 
NtClose_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtClose_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtClose_Check_10_0_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtClose_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtClose_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtClose_SystemCall_6_3_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtClose_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtClose_SystemCall_6_1_7601
	jmp NtClose_SystemCall_Unknown
NtClose_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtClose_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtClose_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtClose_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtClose_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtClose_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtClose_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtClose_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtClose_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtClose_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtClose_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtClose_SystemCall_10_0_19042
	jmp NtClose_SystemCall_Unknown
NtClose_SystemCall_6_1_7600:          
	mov eax, 0x000c
	jmp NtClose_Epilogue
NtClose_SystemCall_6_1_7601:          
	mov eax, 0x000c
	jmp NtClose_Epilogue
NtClose_SystemCall_6_2_XXXX:          
	mov eax, 0x000d
	jmp NtClose_Epilogue
NtClose_SystemCall_6_3_XXXX:          
	mov eax, 0x000e
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10240:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10586:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_14393:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_15063:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_16299:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17134:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17763:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18362:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18363:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_19041:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_19042:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_Unknown:           
	ret
NtClose_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NtFreeVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, RegionSize: PSIZE_T, FreeType: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                             
NtFreeVirtualMemory_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtFreeVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtFreeVirtualMemory_Check_10_0_XXXX
	jmp NtFreeVirtualMemory_SystemCall_Unknown
NtFreeVirtualMemory_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtFreeVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtFreeVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtFreeVirtualMemory_SystemCall_6_3_XXXX
	jmp NtFreeVirtualMemory_SystemCall_Unknown
NtFreeVirtualMemory_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtFreeVirtualMemory_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtFreeVirtualMemory_SystemCall_6_1_7601
	jmp NtFreeVirtualMemory_SystemCall_Unknown
NtFreeVirtualMemory_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtFreeVirtualMemory_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtFreeVirtualMemory_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtFreeVirtualMemory_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtFreeVirtualMemory_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtFreeVirtualMemory_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtFreeVirtualMemory_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtFreeVirtualMemory_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtFreeVirtualMemory_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtFreeVirtualMemory_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtFreeVirtualMemory_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtFreeVirtualMemory_SystemCall_10_0_19042
	jmp NtFreeVirtualMemory_SystemCall_Unknown
NtFreeVirtualMemory_SystemCall_6_1_7600:          
	mov eax, 0x001b
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_6_1_7601:          
	mov eax, 0x001b
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_6_2_XXXX:          
	mov eax, 0x001c
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_6_3_XXXX:          
	mov eax, 0x001d
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_10240:        
	mov eax, 0x001e
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_10586:        
	mov eax, 0x001e
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_14393:        
	mov eax, 0x001e
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_15063:        
	mov eax, 0x001e
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_16299:        
	mov eax, 0x001e
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_17134:        
	mov eax, 0x001e
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_17763:        
	mov eax, 0x001e
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_18362:        
	mov eax, 0x001e
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_18363:        
	mov eax, 0x001e
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_19041:        
	mov eax, 0x001e
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_19042:        
	mov eax, 0x001e
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_Unknown:           
	ret
NtFreeVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NtOpenProcess(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                       
NtOpenProcess_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtOpenProcess_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtOpenProcess_Check_10_0_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtOpenProcess_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtOpenProcess_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtOpenProcess_SystemCall_6_3_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtOpenProcess_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtOpenProcess_SystemCall_6_1_7601
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtOpenProcess_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtOpenProcess_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtOpenProcess_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtOpenProcess_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtOpenProcess_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtOpenProcess_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtOpenProcess_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtOpenProcess_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtOpenProcess_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtOpenProcess_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtOpenProcess_SystemCall_10_0_19042
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_SystemCall_6_1_7600:          
	mov eax, 0x0023
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_1_7601:          
	mov eax, 0x0023
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_2_XXXX:          
	mov eax, 0x0024
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_3_XXXX:          
	mov eax, 0x0025
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10240:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10586:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_14393:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_15063:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_16299:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17134:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17763:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18362:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18363:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_19041:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_19042:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_Unknown:           
	ret
NtOpenProcess_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NtOpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: ACCESS_MASK, TokenHandle: PHANDLE): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                            
NtOpenProcessToken_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtOpenProcessToken_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtOpenProcessToken_Check_10_0_XXXX
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtOpenProcessToken_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtOpenProcessToken_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtOpenProcessToken_SystemCall_6_3_XXXX
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtOpenProcessToken_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtOpenProcessToken_SystemCall_6_1_7601
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtOpenProcessToken_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtOpenProcessToken_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtOpenProcessToken_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtOpenProcessToken_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtOpenProcessToken_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtOpenProcessToken_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtOpenProcessToken_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtOpenProcessToken_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtOpenProcessToken_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtOpenProcessToken_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtOpenProcessToken_SystemCall_10_0_19042
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_SystemCall_6_1_7600:          
	mov eax, 0x00f9
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_1_7601:          
	mov eax, 0x00f9
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_2_XXXX:          
	mov eax, 0x010b
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_3_XXXX:          
	mov eax, 0x010e
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_10240:        
	mov eax, 0x0114
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_10586:        
	mov eax, 0x0117
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_14393:        
	mov eax, 0x0119
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_15063:        
	mov eax, 0x011d
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_16299:        
	mov eax, 0x011f
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_17134:        
	mov eax, 0x0121
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_17763:        
	mov eax, 0x0122
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_18362:        
	mov eax, 0x0123
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_18363:        
	mov eax, 0x0123
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_19041:        
	mov eax, 0x0128
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_19042:        
	mov eax, 0x0128
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_Unknown:           
	ret
NtOpenProcessToken_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NtQuerySystemInformation(SystemInformationClass: SYSTEM_INFORMATION_CLASS, SystemInformation: PVOID, SystemInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                                  
NtQuerySystemInformation_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtQuerySystemInformation_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtQuerySystemInformation_Check_10_0_XXXX
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtQuerySystemInformation_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtQuerySystemInformation_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtQuerySystemInformation_SystemCall_6_3_XXXX
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtQuerySystemInformation_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtQuerySystemInformation_SystemCall_6_1_7601
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtQuerySystemInformation_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtQuerySystemInformation_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtQuerySystemInformation_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtQuerySystemInformation_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtQuerySystemInformation_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtQuerySystemInformation_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtQuerySystemInformation_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtQuerySystemInformation_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtQuerySystemInformation_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtQuerySystemInformation_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtQuerySystemInformation_SystemCall_10_0_19042
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_SystemCall_6_1_7600:          
	mov eax, 0x0033
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_1_7601:          
	mov eax, 0x0033
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_2_XXXX:          
	mov eax, 0x0034
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_3_XXXX:          
	mov eax, 0x0035
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_10240:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_10586:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_14393:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_15063:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_16299:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_17134:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_17763:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_18362:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_18363:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_19041:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_19042:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_Unknown:           
	ret
NtQuerySystemInformation_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NtReadVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: SIZE_T, NumberOfBytesRead: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                             
NtReadVirtualMemory_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtReadVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtReadVirtualMemory_Check_10_0_XXXX
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtReadVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtReadVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtReadVirtualMemory_SystemCall_6_3_XXXX
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtReadVirtualMemory_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtReadVirtualMemory_SystemCall_6_1_7601
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtReadVirtualMemory_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtReadVirtualMemory_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtReadVirtualMemory_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtReadVirtualMemory_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtReadVirtualMemory_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtReadVirtualMemory_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtReadVirtualMemory_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtReadVirtualMemory_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtReadVirtualMemory_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtReadVirtualMemory_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtReadVirtualMemory_SystemCall_10_0_19042
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_SystemCall_6_1_7600:          
	mov eax, 0x003c
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_1_7601:          
	mov eax, 0x003c
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_2_XXXX:          
	mov eax, 0x003d
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_3_XXXX:          
	mov eax, 0x003e
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_10240:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_10586:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_14393:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_15063:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_16299:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_17134:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_17763:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_18362:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_18363:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_19041:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_19042:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_Unknown:           
	ret
NtReadVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NtWriteVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                              
NtWriteVirtualMemory_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtWriteVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtWriteVirtualMemory_Check_10_0_XXXX
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtWriteVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtWriteVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtWriteVirtualMemory_SystemCall_6_3_XXXX
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtWriteVirtualMemory_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtWriteVirtualMemory_SystemCall_6_1_7601
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtWriteVirtualMemory_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtWriteVirtualMemory_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtWriteVirtualMemory_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtWriteVirtualMemory_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtWriteVirtualMemory_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtWriteVirtualMemory_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtWriteVirtualMemory_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtWriteVirtualMemory_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtWriteVirtualMemory_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtWriteVirtualMemory_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtWriteVirtualMemory_SystemCall_10_0_19042
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_SystemCall_6_1_7600:          
	mov eax, 0x0037
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_1_7601:          
	mov eax, 0x0037
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_2_XXXX:          
	mov eax, 0x0038
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_3_XXXX:          
	mov eax, 0x0039
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_10240:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_10586:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_14393:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_15063:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_16299:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_17134:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_17763:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_18362:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_18363:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_19041:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_19042:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_Unknown:           
	ret
NtWriteVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

