{.passC:"-masm=intel".}

# GetTEBAsm64 -> SFvaGcZvCStqpimm
# NtQuerySystemInformation -> ubyRCpOytBpCkrgW
# NtOpenProcess -> sjGfpzWwEqIMryMW
# NtOpenProcessToken -> nZFSjOMSXlJYIfGF
# NtAdjustPrivilegesToken -> KDbJZsqcZWqlAZpm
# NtAllocateVirtualMemory -> xANRBkMmvNMFvMkf
# NtFreeVirtualMemory -> yZhhnBMbyifaYyWA
# NtReadVirtualMemory -> VHlCcYwobYwUwxqH
# NtWriteVirtualMemory -> VVkixCSJcidoBZgM
# NtClose -> CXmzjWrWwTeuSBjT

proc SFvaGcZvCStqpimm*(): LPVOID {.asmNoStackFrame.} =
    asm """
	mov rax, qword ptr gs:[0x30]
	ret
    """

proc KDbJZsqcZWqlAZpm*(TokenHandle: HANDLE, DisableAllPrivileges: BOOLEAN, NewState: PTOKEN_PRIVILEGES, BufferLength: ULONG, PreviousState: PTOKEN_PRIVILEGES, ReturnLength: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                                 
KDbJZsqcZWqlAZpm_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  KDbJZsqcZWqlAZpm_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  KDbJZsqcZWqlAZpm_Check_10_0_XXXX
	jmp KDbJZsqcZWqlAZpm_SystemCall_Unknown
KDbJZsqcZWqlAZpm_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  KDbJZsqcZWqlAZpm_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  KDbJZsqcZWqlAZpm_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  KDbJZsqcZWqlAZpm_SystemCall_6_3_XXXX
	jmp KDbJZsqcZWqlAZpm_SystemCall_Unknown
KDbJZsqcZWqlAZpm_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  KDbJZsqcZWqlAZpm_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  KDbJZsqcZWqlAZpm_SystemCall_6_1_7601
	jmp KDbJZsqcZWqlAZpm_SystemCall_Unknown
KDbJZsqcZWqlAZpm_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  KDbJZsqcZWqlAZpm_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  KDbJZsqcZWqlAZpm_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  KDbJZsqcZWqlAZpm_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  KDbJZsqcZWqlAZpm_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  KDbJZsqcZWqlAZpm_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  KDbJZsqcZWqlAZpm_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  KDbJZsqcZWqlAZpm_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  KDbJZsqcZWqlAZpm_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  KDbJZsqcZWqlAZpm_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  KDbJZsqcZWqlAZpm_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  KDbJZsqcZWqlAZpm_SystemCall_10_0_19042
	jmp KDbJZsqcZWqlAZpm_SystemCall_Unknown
KDbJZsqcZWqlAZpm_SystemCall_6_1_7600:          
	mov eax, 0x003e
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_6_1_7601:          
	mov eax, 0x003e
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_6_2_XXXX:          
	mov eax, 0x003f
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_6_3_XXXX:          
	mov eax, 0x0040
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_10_0_10240:        
	mov eax, 0x0041
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_10_0_10586:        
	mov eax, 0x0041
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_10_0_14393:        
	mov eax, 0x0041
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_10_0_15063:        
	mov eax, 0x0041
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_10_0_16299:        
	mov eax, 0x0041
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_10_0_17134:        
	mov eax, 0x0041
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_10_0_17763:        
	mov eax, 0x0041
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_10_0_18362:        
	mov eax, 0x0041
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_10_0_18363:        
	mov eax, 0x0041
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_10_0_19041:        
	mov eax, 0x0041
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_10_0_19042:        
	mov eax, 0x0041
	jmp KDbJZsqcZWqlAZpm_Epilogue
KDbJZsqcZWqlAZpm_SystemCall_Unknown:           
	ret
KDbJZsqcZWqlAZpm_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc xANRBkMmvNMFvMkf*(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                                 
xANRBkMmvNMFvMkf_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  xANRBkMmvNMFvMkf_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  xANRBkMmvNMFvMkf_Check_10_0_XXXX
	jmp xANRBkMmvNMFvMkf_SystemCall_Unknown
xANRBkMmvNMFvMkf_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  xANRBkMmvNMFvMkf_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  xANRBkMmvNMFvMkf_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  xANRBkMmvNMFvMkf_SystemCall_6_3_XXXX
	jmp xANRBkMmvNMFvMkf_SystemCall_Unknown
xANRBkMmvNMFvMkf_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  xANRBkMmvNMFvMkf_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  xANRBkMmvNMFvMkf_SystemCall_6_1_7601
	jmp xANRBkMmvNMFvMkf_SystemCall_Unknown
xANRBkMmvNMFvMkf_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  xANRBkMmvNMFvMkf_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  xANRBkMmvNMFvMkf_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  xANRBkMmvNMFvMkf_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  xANRBkMmvNMFvMkf_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  xANRBkMmvNMFvMkf_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  xANRBkMmvNMFvMkf_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  xANRBkMmvNMFvMkf_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  xANRBkMmvNMFvMkf_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  xANRBkMmvNMFvMkf_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  xANRBkMmvNMFvMkf_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  xANRBkMmvNMFvMkf_SystemCall_10_0_19042
	jmp xANRBkMmvNMFvMkf_SystemCall_Unknown
xANRBkMmvNMFvMkf_SystemCall_6_1_7600:          
	mov eax, 0x0015
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_6_1_7601:          
	mov eax, 0x0015
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_6_2_XXXX:          
	mov eax, 0x0016
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_6_3_XXXX:          
	mov eax, 0x0017
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_10_0_10240:        
	mov eax, 0x0018
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_10_0_10586:        
	mov eax, 0x0018
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_10_0_14393:        
	mov eax, 0x0018
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_10_0_15063:        
	mov eax, 0x0018
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_10_0_16299:        
	mov eax, 0x0018
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_10_0_17134:        
	mov eax, 0x0018
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_10_0_17763:        
	mov eax, 0x0018
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_10_0_18362:        
	mov eax, 0x0018
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_10_0_18363:        
	mov eax, 0x0018
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_10_0_19041:        
	mov eax, 0x0018
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_10_0_19042:        
	mov eax, 0x0018
	jmp xANRBkMmvNMFvMkf_Epilogue
xANRBkMmvNMFvMkf_SystemCall_Unknown:           
	ret
xANRBkMmvNMFvMkf_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc CXmzjWrWwTeuSBjT*(Handle: HANDLE): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                 
CXmzjWrWwTeuSBjT_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  CXmzjWrWwTeuSBjT_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  CXmzjWrWwTeuSBjT_Check_10_0_XXXX
	jmp CXmzjWrWwTeuSBjT_SystemCall_Unknown
CXmzjWrWwTeuSBjT_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  CXmzjWrWwTeuSBjT_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  CXmzjWrWwTeuSBjT_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  CXmzjWrWwTeuSBjT_SystemCall_6_3_XXXX
	jmp CXmzjWrWwTeuSBjT_SystemCall_Unknown
CXmzjWrWwTeuSBjT_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  CXmzjWrWwTeuSBjT_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  CXmzjWrWwTeuSBjT_SystemCall_6_1_7601
	jmp CXmzjWrWwTeuSBjT_SystemCall_Unknown
CXmzjWrWwTeuSBjT_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  CXmzjWrWwTeuSBjT_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  CXmzjWrWwTeuSBjT_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  CXmzjWrWwTeuSBjT_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  CXmzjWrWwTeuSBjT_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  CXmzjWrWwTeuSBjT_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  CXmzjWrWwTeuSBjT_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  CXmzjWrWwTeuSBjT_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  CXmzjWrWwTeuSBjT_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  CXmzjWrWwTeuSBjT_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  CXmzjWrWwTeuSBjT_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  CXmzjWrWwTeuSBjT_SystemCall_10_0_19042
	jmp CXmzjWrWwTeuSBjT_SystemCall_Unknown
CXmzjWrWwTeuSBjT_SystemCall_6_1_7600:          
	mov eax, 0x000c
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_6_1_7601:          
	mov eax, 0x000c
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_6_2_XXXX:          
	mov eax, 0x000d
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_6_3_XXXX:          
	mov eax, 0x000e
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_10_0_10240:        
	mov eax, 0x000f
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_10_0_10586:        
	mov eax, 0x000f
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_10_0_14393:        
	mov eax, 0x000f
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_10_0_15063:        
	mov eax, 0x000f
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_10_0_16299:        
	mov eax, 0x000f
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_10_0_17134:        
	mov eax, 0x000f
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_10_0_17763:        
	mov eax, 0x000f
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_10_0_18362:        
	mov eax, 0x000f
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_10_0_18363:        
	mov eax, 0x000f
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_10_0_19041:        
	mov eax, 0x000f
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_10_0_19042:        
	mov eax, 0x000f
	jmp CXmzjWrWwTeuSBjT_Epilogue
CXmzjWrWwTeuSBjT_SystemCall_Unknown:           
	ret
CXmzjWrWwTeuSBjT_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc yZhhnBMbyifaYyWA*(ProcessHandle: HANDLE, BaseAddress: PVOID, RegionSize: PSIZE_T, FreeType: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                             
yZhhnBMbyifaYyWA_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  yZhhnBMbyifaYyWA_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  yZhhnBMbyifaYyWA_Check_10_0_XXXX
	jmp yZhhnBMbyifaYyWA_SystemCall_Unknown
yZhhnBMbyifaYyWA_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  yZhhnBMbyifaYyWA_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  yZhhnBMbyifaYyWA_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  yZhhnBMbyifaYyWA_SystemCall_6_3_XXXX
	jmp yZhhnBMbyifaYyWA_SystemCall_Unknown
yZhhnBMbyifaYyWA_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  yZhhnBMbyifaYyWA_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  yZhhnBMbyifaYyWA_SystemCall_6_1_7601
	jmp yZhhnBMbyifaYyWA_SystemCall_Unknown
yZhhnBMbyifaYyWA_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  yZhhnBMbyifaYyWA_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  yZhhnBMbyifaYyWA_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  yZhhnBMbyifaYyWA_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  yZhhnBMbyifaYyWA_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  yZhhnBMbyifaYyWA_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  yZhhnBMbyifaYyWA_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  yZhhnBMbyifaYyWA_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  yZhhnBMbyifaYyWA_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  yZhhnBMbyifaYyWA_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  yZhhnBMbyifaYyWA_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  yZhhnBMbyifaYyWA_SystemCall_10_0_19042
	jmp yZhhnBMbyifaYyWA_SystemCall_Unknown
yZhhnBMbyifaYyWA_SystemCall_6_1_7600:          
	mov eax, 0x001b
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_6_1_7601:          
	mov eax, 0x001b
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_6_2_XXXX:          
	mov eax, 0x001c
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_6_3_XXXX:          
	mov eax, 0x001d
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_10_0_10240:        
	mov eax, 0x001e
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_10_0_10586:        
	mov eax, 0x001e
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_10_0_14393:        
	mov eax, 0x001e
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_10_0_15063:        
	mov eax, 0x001e
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_10_0_16299:        
	mov eax, 0x001e
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_10_0_17134:        
	mov eax, 0x001e
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_10_0_17763:        
	mov eax, 0x001e
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_10_0_18362:        
	mov eax, 0x001e
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_10_0_18363:        
	mov eax, 0x001e
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_10_0_19041:        
	mov eax, 0x001e
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_10_0_19042:        
	mov eax, 0x001e
	jmp yZhhnBMbyifaYyWA_Epilogue
yZhhnBMbyifaYyWA_SystemCall_Unknown:           
	ret
yZhhnBMbyifaYyWA_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc sjGfpzWwEqIMryMW*(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                       
sjGfpzWwEqIMryMW_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  sjGfpzWwEqIMryMW_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  sjGfpzWwEqIMryMW_Check_10_0_XXXX
	jmp sjGfpzWwEqIMryMW_SystemCall_Unknown
sjGfpzWwEqIMryMW_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  sjGfpzWwEqIMryMW_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  sjGfpzWwEqIMryMW_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  sjGfpzWwEqIMryMW_SystemCall_6_3_XXXX
	jmp sjGfpzWwEqIMryMW_SystemCall_Unknown
sjGfpzWwEqIMryMW_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  sjGfpzWwEqIMryMW_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  sjGfpzWwEqIMryMW_SystemCall_6_1_7601
	jmp sjGfpzWwEqIMryMW_SystemCall_Unknown
sjGfpzWwEqIMryMW_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  sjGfpzWwEqIMryMW_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  sjGfpzWwEqIMryMW_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  sjGfpzWwEqIMryMW_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  sjGfpzWwEqIMryMW_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  sjGfpzWwEqIMryMW_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  sjGfpzWwEqIMryMW_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  sjGfpzWwEqIMryMW_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  sjGfpzWwEqIMryMW_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  sjGfpzWwEqIMryMW_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  sjGfpzWwEqIMryMW_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  sjGfpzWwEqIMryMW_SystemCall_10_0_19042
	jmp sjGfpzWwEqIMryMW_SystemCall_Unknown
sjGfpzWwEqIMryMW_SystemCall_6_1_7600:          
	mov eax, 0x0023
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_6_1_7601:          
	mov eax, 0x0023
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_6_2_XXXX:          
	mov eax, 0x0024
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_6_3_XXXX:          
	mov eax, 0x0025
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_10_0_10240:        
	mov eax, 0x0026
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_10_0_10586:        
	mov eax, 0x0026
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_10_0_14393:        
	mov eax, 0x0026
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_10_0_15063:        
	mov eax, 0x0026
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_10_0_16299:        
	mov eax, 0x0026
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_10_0_17134:        
	mov eax, 0x0026
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_10_0_17763:        
	mov eax, 0x0026
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_10_0_18362:        
	mov eax, 0x0026
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_10_0_18363:        
	mov eax, 0x0026
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_10_0_19041:        
	mov eax, 0x0026
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_10_0_19042:        
	mov eax, 0x0026
	jmp sjGfpzWwEqIMryMW_Epilogue
sjGfpzWwEqIMryMW_SystemCall_Unknown:           
	ret
sjGfpzWwEqIMryMW_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc nZFSjOMSXlJYIfGF*(ProcessHandle: HANDLE, DesiredAccess: ACCESS_MASK, TokenHandle: PHANDLE): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                            
nZFSjOMSXlJYIfGF_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  nZFSjOMSXlJYIfGF_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  nZFSjOMSXlJYIfGF_Check_10_0_XXXX
	jmp nZFSjOMSXlJYIfGF_SystemCall_Unknown
nZFSjOMSXlJYIfGF_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  nZFSjOMSXlJYIfGF_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  nZFSjOMSXlJYIfGF_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  nZFSjOMSXlJYIfGF_SystemCall_6_3_XXXX
	jmp nZFSjOMSXlJYIfGF_SystemCall_Unknown
nZFSjOMSXlJYIfGF_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  nZFSjOMSXlJYIfGF_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  nZFSjOMSXlJYIfGF_SystemCall_6_1_7601
	jmp nZFSjOMSXlJYIfGF_SystemCall_Unknown
nZFSjOMSXlJYIfGF_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  nZFSjOMSXlJYIfGF_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  nZFSjOMSXlJYIfGF_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  nZFSjOMSXlJYIfGF_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  nZFSjOMSXlJYIfGF_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  nZFSjOMSXlJYIfGF_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  nZFSjOMSXlJYIfGF_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  nZFSjOMSXlJYIfGF_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  nZFSjOMSXlJYIfGF_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  nZFSjOMSXlJYIfGF_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  nZFSjOMSXlJYIfGF_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  nZFSjOMSXlJYIfGF_SystemCall_10_0_19042
	jmp nZFSjOMSXlJYIfGF_SystemCall_Unknown
nZFSjOMSXlJYIfGF_SystemCall_6_1_7600:          
	mov eax, 0x00f9
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_6_1_7601:          
	mov eax, 0x00f9
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_6_2_XXXX:          
	mov eax, 0x010b
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_6_3_XXXX:          
	mov eax, 0x010e
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_10_0_10240:        
	mov eax, 0x0114
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_10_0_10586:        
	mov eax, 0x0117
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_10_0_14393:        
	mov eax, 0x0119
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_10_0_15063:        
	mov eax, 0x011d
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_10_0_16299:        
	mov eax, 0x011f
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_10_0_17134:        
	mov eax, 0x0121
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_10_0_17763:        
	mov eax, 0x0122
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_10_0_18362:        
	mov eax, 0x0123
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_10_0_18363:        
	mov eax, 0x0123
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_10_0_19041:        
	mov eax, 0x0128
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_10_0_19042:        
	mov eax, 0x0128
	jmp nZFSjOMSXlJYIfGF_Epilogue
nZFSjOMSXlJYIfGF_SystemCall_Unknown:           
	ret
nZFSjOMSXlJYIfGF_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc ubyRCpOytBpCkrgW*(SystemInformationClass: SYSTEM_INFORMATION_CLASS, SystemInformation: PVOID, SystemInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                                  
ubyRCpOytBpCkrgW_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  ubyRCpOytBpCkrgW_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  ubyRCpOytBpCkrgW_Check_10_0_XXXX
	jmp ubyRCpOytBpCkrgW_SystemCall_Unknown
ubyRCpOytBpCkrgW_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  ubyRCpOytBpCkrgW_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  ubyRCpOytBpCkrgW_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  ubyRCpOytBpCkrgW_SystemCall_6_3_XXXX
	jmp ubyRCpOytBpCkrgW_SystemCall_Unknown
ubyRCpOytBpCkrgW_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  ubyRCpOytBpCkrgW_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  ubyRCpOytBpCkrgW_SystemCall_6_1_7601
	jmp ubyRCpOytBpCkrgW_SystemCall_Unknown
ubyRCpOytBpCkrgW_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  ubyRCpOytBpCkrgW_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  ubyRCpOytBpCkrgW_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  ubyRCpOytBpCkrgW_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  ubyRCpOytBpCkrgW_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  ubyRCpOytBpCkrgW_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  ubyRCpOytBpCkrgW_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  ubyRCpOytBpCkrgW_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  ubyRCpOytBpCkrgW_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  ubyRCpOytBpCkrgW_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  ubyRCpOytBpCkrgW_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  ubyRCpOytBpCkrgW_SystemCall_10_0_19042
	jmp ubyRCpOytBpCkrgW_SystemCall_Unknown
ubyRCpOytBpCkrgW_SystemCall_6_1_7600:          
	mov eax, 0x0033
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_6_1_7601:          
	mov eax, 0x0033
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_6_2_XXXX:          
	mov eax, 0x0034
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_6_3_XXXX:          
	mov eax, 0x0035
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_10_0_10240:        
	mov eax, 0x0036
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_10_0_10586:        
	mov eax, 0x0036
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_10_0_14393:        
	mov eax, 0x0036
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_10_0_15063:        
	mov eax, 0x0036
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_10_0_16299:        
	mov eax, 0x0036
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_10_0_17134:        
	mov eax, 0x0036
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_10_0_17763:        
	mov eax, 0x0036
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_10_0_18362:        
	mov eax, 0x0036
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_10_0_18363:        
	mov eax, 0x0036
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_10_0_19041:        
	mov eax, 0x0036
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_10_0_19042:        
	mov eax, 0x0036
	jmp ubyRCpOytBpCkrgW_Epilogue
ubyRCpOytBpCkrgW_SystemCall_Unknown:           
	ret
ubyRCpOytBpCkrgW_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc VHlCcYwobYwUwxqH*(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: SIZE_T, NumberOfBytesRead: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                             
VHlCcYwobYwUwxqH_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  VHlCcYwobYwUwxqH_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  VHlCcYwobYwUwxqH_Check_10_0_XXXX
	jmp VHlCcYwobYwUwxqH_SystemCall_Unknown
VHlCcYwobYwUwxqH_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  VHlCcYwobYwUwxqH_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  VHlCcYwobYwUwxqH_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  VHlCcYwobYwUwxqH_SystemCall_6_3_XXXX
	jmp VHlCcYwobYwUwxqH_SystemCall_Unknown
VHlCcYwobYwUwxqH_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  VHlCcYwobYwUwxqH_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  VHlCcYwobYwUwxqH_SystemCall_6_1_7601
	jmp VHlCcYwobYwUwxqH_SystemCall_Unknown
VHlCcYwobYwUwxqH_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  VHlCcYwobYwUwxqH_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  VHlCcYwobYwUwxqH_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  VHlCcYwobYwUwxqH_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  VHlCcYwobYwUwxqH_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  VHlCcYwobYwUwxqH_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  VHlCcYwobYwUwxqH_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  VHlCcYwobYwUwxqH_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  VHlCcYwobYwUwxqH_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  VHlCcYwobYwUwxqH_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  VHlCcYwobYwUwxqH_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  VHlCcYwobYwUwxqH_SystemCall_10_0_19042
	jmp VHlCcYwobYwUwxqH_SystemCall_Unknown
VHlCcYwobYwUwxqH_SystemCall_6_1_7600:          
	mov eax, 0x003c
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_6_1_7601:          
	mov eax, 0x003c
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_6_2_XXXX:          
	mov eax, 0x003d
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_6_3_XXXX:          
	mov eax, 0x003e
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_10_0_10240:        
	mov eax, 0x003f
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_10_0_10586:        
	mov eax, 0x003f
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_10_0_14393:        
	mov eax, 0x003f
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_10_0_15063:        
	mov eax, 0x003f
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_10_0_16299:        
	mov eax, 0x003f
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_10_0_17134:        
	mov eax, 0x003f
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_10_0_17763:        
	mov eax, 0x003f
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_10_0_18362:        
	mov eax, 0x003f
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_10_0_18363:        
	mov eax, 0x003f
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_10_0_19041:        
	mov eax, 0x003f
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_10_0_19042:        
	mov eax, 0x003f
	jmp VHlCcYwobYwUwxqH_Epilogue
VHlCcYwobYwUwxqH_SystemCall_Unknown:           
	ret
VHlCcYwobYwUwxqH_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc VVkixCSJcidoBZgM*(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                              
VVkixCSJcidoBZgM_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  VVkixCSJcidoBZgM_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  VVkixCSJcidoBZgM_Check_10_0_XXXX
	jmp VVkixCSJcidoBZgM_SystemCall_Unknown
VVkixCSJcidoBZgM_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  VVkixCSJcidoBZgM_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  VVkixCSJcidoBZgM_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  VVkixCSJcidoBZgM_SystemCall_6_3_XXXX
	jmp VVkixCSJcidoBZgM_SystemCall_Unknown
VVkixCSJcidoBZgM_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  VVkixCSJcidoBZgM_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  VVkixCSJcidoBZgM_SystemCall_6_1_7601
	jmp VVkixCSJcidoBZgM_SystemCall_Unknown
VVkixCSJcidoBZgM_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  VVkixCSJcidoBZgM_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  VVkixCSJcidoBZgM_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  VVkixCSJcidoBZgM_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  VVkixCSJcidoBZgM_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  VVkixCSJcidoBZgM_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  VVkixCSJcidoBZgM_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  VVkixCSJcidoBZgM_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  VVkixCSJcidoBZgM_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  VVkixCSJcidoBZgM_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  VVkixCSJcidoBZgM_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  VVkixCSJcidoBZgM_SystemCall_10_0_19042
	jmp VVkixCSJcidoBZgM_SystemCall_Unknown
VVkixCSJcidoBZgM_SystemCall_6_1_7600:          
	mov eax, 0x0037
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_6_1_7601:          
	mov eax, 0x0037
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_6_2_XXXX:          
	mov eax, 0x0038
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_6_3_XXXX:          
	mov eax, 0x0039
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_10_0_10240:        
	mov eax, 0x003a
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_10_0_10586:        
	mov eax, 0x003a
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_10_0_14393:        
	mov eax, 0x003a
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_10_0_15063:        
	mov eax, 0x003a
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_10_0_16299:        
	mov eax, 0x003a
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_10_0_17134:        
	mov eax, 0x003a
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_10_0_17763:        
	mov eax, 0x003a
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_10_0_18362:        
	mov eax, 0x003a
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_10_0_18363:        
	mov eax, 0x003a
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_10_0_19041:        
	mov eax, 0x003a
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_10_0_19042:        
	mov eax, 0x003a
	jmp VVkixCSJcidoBZgM_Epilogue
VVkixCSJcidoBZgM_SystemCall_Unknown:           
	ret
VVkixCSJcidoBZgM_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

