# NimlineWhispers #

A _very_ proof-of-concept port of Outflank's [InlineWhispers](https://github.com/outflanknl/InlineWhispers) tool, adapted to output inline assembly for Nim projects.

This uses the same process of taking output from [SysWhispers](https://github.com/jthuraisamy/SysWhispers), but also parses the Syscalls.h file to include function return types and arguments in the outputted inline assembly.

### How do I set this up? ###

This is basically the same as InlineWhispers, but including for completeness.

 * (Optionally) Install [SysWhispers](https://github.com/jthuraisamy/SysWhispers)
    * `git clone https://github.com/jthuraisamy/SysWhispers.git `
    * `cd SysWhispers`
    * `pip3 install -r .\requirements.txt`
    * `py .\syswhispers.py --versions 7,8,10 -o syscalls` was used to generate the included `syscalls.asm` and `syscalls.h`.
 * Clone this repository.
 * Update which functions are required in `functions.txt` to include only necessary functions from syscalls.asm.
 * Run the ``python3 NimlineWhispers.py`` command (additional flags listed below) to generate the inline assembly (`syscalls.nim`) file - example in the repo.
 * Add `include syscalls` to your Nim project.

An example of integrating NimlineWhispers output with your project can be seen in this [blog.](https://ajpc500.github.io/nim/Shellcode-Injection-using-Nim-and-Syscalls/)

### Randomised Function Names ###

To evade detection based on the presence of function names in our Nim executables (as outlined in [@ShitSecure](https://twitter.com/ShitSecure)'s blog [here](https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/)), NimlineWhispers can be run with a `--randomise` flag, as follows:

```
python3 NimlineWhispers.py --randomise


             %              ..%%%%%#               %/.                  
           /%%%%%,.%%%%%%%%%%%%%%%%%%%%%%%%%%%%.%%%%%%                  
       . #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.               
  %%*.%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% ,%%         
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.         
    #%%%%%%%%%%%%%%.                         %%%%%%%%%%%%%%%%           
      %%%%%%%(                                     %%%%%%%%%            
    &   %%#                                           .%%  ..           
     &&.                          .                     . #&            
      &&&&.               . %&&&&&&&&.                 &&&&             
       &&&&&&&.. .   . (&&&&&&&&&&&&&&&&&%. .     .&&&&&&&              
       .%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&               
         #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                
           ,&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                  
               &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                     
                   &&&&&&&&&&&&&&&&&&&&&&&&&&&                          
                            %&&&&&&&&.                                  
                                                NimlineWhispers
                                                @ajpc500 2021

[i] in  syscalls.asm
[i] out syscalls.nim
[i] Function filter file "functions.txt" contains 10 functions.
[i] Found return types for 10 functions.
[i] Producing randomised function mapping...
        GetTEBAsm64 -> SFvaGcZvCStqpimm
        NtQuerySystemInformation -> ubyRCpOytBpCkrgW
        NtOpenProcess -> sjGfpzWwEqIMryMW
        NtOpenProcessToken -> nZFSjOMSXlJYIfGF
        NtAdjustPrivilegesToken -> KDbJZsqcZWqlAZpm
        NtAllocateVirtualMemory -> xANRBkMmvNMFvMkf
        NtFreeVirtualMemory -> yZhhnBMbyifaYyWA
        NtReadVirtualMemory -> VHlCcYwobYwUwxqH
        NtWriteVirtualMemory -> VVkixCSJcidoBZgM
        NtClose -> CXmzjWrWwTeuSBjT
[+] Success! Outputted to syscalls.nim
```

For easy of integration, the mapping shown in the command-line is added a comment to the top of the outputted `syscalls.nim` file. As below (including the first function to demonstrate the output):

```
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
```
Notably your function definitions such the below will need to be updated with the randomised names too.

```
EXTERN_C NTSTATUS NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);
```
Should become:

```
EXTERN_C NTSTATUS sjGfpzWwEqIMryMW(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);
```

`syscalls_rand.nim` is included as an example output of this randomisation function.

### Limitations ###

 * 64-bit only.

### Credits ###

 * @Outflank and @\_DaWouw for InlineWhispers
 * @byt3bl33d3r for his incredibly informative [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim/) repository
 * The assembly code used within this tool is based on the assembly output from the 
[SysWhispers](https://github.com/jthuraisamy/SysWhispers) tool from [@Jackson_T](https://twitter.com/Jackson_T).
 * All people credited for [SysWhispers](https://github.com/jthuraisamy/SysWhispers#credits)
