# ASM R5900
A MIPS R5900 (Also known as Emotion Engine or Toshiba TX79) analyzer and disassembler for radare2.

## Install
Change directory to anal/p/ and run
```bash
make -f anal_r5900.mk all
make -f anal_r5900.mk install
```
to install the analyzer.

Change directory to asm/p/ and run
```bash
make -f asm_r5900.mk all
make -f asm_r5900.mk install
```
to install the disassembler.

## Features
Easy to crash, cause segment fault, break your stack, etc.

The disassembler support a full range of instruction set of the r5900.

I also implemented a naive assembler in asm_r5900, but the function is very limited, maybe I will improve it in the future.

## Known Bugs
If a subu follows a lui, though the esil will give the calculated result, the corresponding reference flag will not be found and added. I have no idea what is wrong.

## After Installed
After installed the plugin, though the sdb cc is not prepared, the mips' sdb is fine, you may use it. However, it is seems that the default cc is n32, but in most spec., the reg name is o32. I have not deal with the alias, you should alternate the o32 name to n32 in the reg spec if you need it.

## TODO
* The full support of esil.
* The full support of instuctions analysing definition.
* Get rid of inscodec.
