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
 * Run the ``python NimlineWhispers.py`` command to generate the inline assembly (`syscalls.nim`) file - example in the repo.
 * Add `include syscalls` to your Nim project.

### Limitations ###

 * 64-bit only.

### Credits ###

 * @Outflank and @\_DaWouw for InlineWhispers
 * @byt3bl33d3r for his incredibly informative [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim/) repository
 * The assembly code used within this tool is based on the assembly output from the 
[SysWhispers](https://github.com/jthuraisamy/SysWhispers) tool from [@Jackson_T](https://twitter.com/Jackson_T).
 * All people credited for [SysWhispers](https://github.com/jthuraisamy/SysWhispers#credits)
