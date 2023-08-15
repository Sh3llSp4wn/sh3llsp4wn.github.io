---
layout: post
title: Offensive Tool Development - The Shellcode Compiler Was Right There All Along... (Part 2)
---
*Apparently, I need to put something here so a section title doesn't become the preview text...*

# A "Shellcode" configuration for the Linux Toolchain

I am no longer going to continue comparing this technique to bootloader construction. The section in my previous post was mostly just to be illustrative of the toolchain's flexibility and to introduce this concept via the technology that inspired this line of research. From now on this post will be more direct with what we are doing. 

Okay? Lets do this.
![](/images/netsec.png)

We are going to need some ingredients to make this work. So, lets look at our C example from earlier.

```c
static char* msg = "Hello, Friend\n";

int main(){
  int size = write(1, msg, sizeof(msg));
  return 0;                                    
}
```

There are some implied dependencies to even this short snippit of code that `gcc` hides from the developer. This is a good thing, because for the vast majority of development use cases the developer does not care where `write` comes from. They just want a stable interface.

As a side note, this code also assumes a specific kind of UNIX compatible environment via the implicit use of `1` as the file descriptor of `STDOUT`.

So, where does `write` come from? Usually it is provided by the c standard library. `gcc` allows for configurations that do not use this library. The default behavior, however, is to use it. This is unsutible for shellcode development. We're going to need our own. 

## The Compiler's 3 stages

Welcome back to CompSci 101, bitches. 

![I was a smoker in college, so let me have this.](/images/netsec2.png)

It's time for a quick review of the steps used by the toolchain to create the output binary. There are three standard steps. These steps are as follows.

* Lexical Processing (C -> AST)
* Compilation (AST -> ASM/.o)
* Linking (.o -> .elf/.so/etc)

The main step we are concerned with here is the linking step. That's where the core of this set of techniques come from. The linker's job is to resolve symbols between object files and construct the requested binary from them. This is done via a *linker script* (this part is important, so remember it.) Object files are, mostly, 1-to-1 with the `.c` files that functions exist in. The general pattern that C projects follow is to have the compiler generate object files from all of the `.c` files and then use the linker to bind all of the resultant `.o` files into the final binary(ies).

This allows us to define any of the functions that we use in our project. If we define `write` and use it in our project, the linker will generally prefer to use the implementation provided by the project. User defined code nearly always has preference to library code durring this step. (Specific configurations violate this principal, but that is out of scope here.).

That was technical, so lets take a step back and contextualize this. We want the above C code to become shellcode. As it stands, running `gcc hello.c` will just produce an `a.out`. This file is a linux ELF which relies on the standard library's implementation of `write`. Our next step is to figure out how to elemenate this dependency and how to instruct the linker to create the kind of file we want. 

## Linker Scripts, and other witchcraft punishable by the church

Linkers use scripts to define the file format of the binary it is tasked to create. The ELF and SO file formats are defined via these scripts. These scripts are, usually, not exposed to the developer using `gcc` and `ld`

In total honesty, these scripts are still somewhat of an enigma to me. I was able to cobble together one that created shellcode by, mostly, trial and error.  That script is as follows.

```
MEMORY
  {
    RAM : ORIGIN = 0, LENGTH = 4M
  }

REGION_ALIAS("REGION_TEXT", RAM);
REGION_ALIAS("REGION_RODATA", RAM);
REGION_ALIAS("REGION_DATA", RAM);
REGION_ALIAS("REGION_BSS", RAM);

ENTRY(start_external)

SECTIONS
  {
    .text :
      {
        /*
         * Align on 1 may cause breakage.
         * SO, don't say I didn't warn you.
         */
        . = ALIGN(1);
        /*
         * hmm yes, the text segment address 
         * is made out of text segment address
         */
        *(.text)
      } > REGION_TEXT
    .rodata :
      {
        /* I'll not make the same joke twice
         * but basically just say the .rodata
         * pointer exists at the current cursor
         * location 
         */
        *(.rodata)
        /*rodata_end = .;*/
       } > REGION_RODATA
   }
    /*.data : AT (rodata_end)
      {
        data_start = .;
        *(.data)
      } > REGION_DATA
    data_size = SIZEOF(.data);
    data_load_start = LOADADDR(.data);
    .bss :
      {
        *(.bss)
      } > REGION_BSS
  }*/
```


I understand that this script is pretty hidious, so if anyone has more experience with these things, please reach out. I would love to learn more.

This script expects the symbol `start_external` to exist. Any set of object files that have this symbol defined should technically link via this script, but YMMV.

This leads us to something we have to define ourselves. This linker script expects `start_external` to exist and to be the entry point. So lets do that. Right now this is x86\_64 specific, but other `start.s` variants can be created that serve other architectures. 


```assembly
.text
.intel_syntax noprefix
.extern _start
.global start_external
.equ SYS_exit, 60

start_external:
call _start
mov rax, SYS_exit
syscall
```

Now for a little bit of congratulations to ourselves. Let's talk about what this gives us. The linker script above puts the `start_external` function as the first byte of the output file (as long as `start.o` is the first file given to the linker). This means as long as we implement `start_external` we have shellcode that is linked by this script with only one architecture dependent assembly file. 

We do, however, need this asm file to call into our C code. That is via the expectation of a defined `_start` function.

All the above code does is define a text segment (where binary code lives in an ELF file), call into `_start`, and then `exit()` via direct syscall invocation.


So, let's modify our C code to define the new C entry point `_start`.

```c
static char* msg = "Hello, Friend\n";

int _start(){
  int size = write(1, msg, sizeof(msg));
  return 0;                                    
}
```

Another thing to note is that we can define the function prototype of `_start` to be anything we like. If we make the assumption that the shellcode we generate is going to be used via a call to a function pointer then we can define this function prototype to accept arguments. The only limitation to this I can think of is that `start_external` must not modify register state. (If you implement this for 32 bit x86 then you may want to switch out the `call` for a `jmp` and exit from your shellcode itself, so the stack remains how the callee function expects it.)

Also, after `_start` ends execution our `start_external` function can be programmed to do anything. This implementation just calls exit, but it could also be used to return execution to the infected process, or do any other repair operations that is needed post-execution of the shellcode. 

That leaves `write` and what we are going to do about it.

## The Interface File

The nice thing about `write` is that it is a direct syscall. To invoke it we load the registers mentioned in the previous post, load the A register with the syscall number (RAX/EAX/etc), and invoke the user mode interupt. The register patterns are below.

```python
syscall_reg_seq = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
usermode_reg_seq = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
```

As you can see these are pretty close to one another. This has led to some truely insidious bugs in the course of this research. This is also just two of the calling conventions based on registers. `usermode_reg_seq` is the sequence needed for calling system libraries (such as the c standard library), and `syscall_reg_seq` is how you order arguments for the kernel.

Now, let's actually provide this syscall to the program we are writing. We will do so via a small assembly program. That puts us at two small architecture specific assembly files. This is actually all we will need.

```assembly
.text
.intel_syntax noprefix

.global _write

.equ SYS_write, 1

# just load rax with the number and syscall
.macro direct_syscall syscall_number, symbol
\symbol:
mov rax, \syscall_number
syscall
ret
# end the macro
.endm 

# generate the code
direct_syscall SYS_write, _write
```

Nice! Now we have a macro we can wrap around any syscall we want with a small edit to this file. 

![](/images/netsec.png)


For example to add `read` we'd just need to add the following:

```assembly
.text
.intel_syntax noprefix

.global _write
.global _read

.equ SYS_read, 0
.equ SYS_write, 1

# just load rax with the number and syscall
.macro direct_syscall syscall_number, symbol
\symbol:
mov rax, \syscall_number
syscall
ret
# end the macro
.endm 

# generate the code
direct_syscall SYS_write, _write
direct_syscall SYS_read, _read
```

Let's make the final modifications to the `hello.c` we have been working on:

```c
static char* msg = "Hello, Friend\n";
extern int _write(int, const char[], int);

int _start(){
  int size = _write(1, msg, sizeof(msg));
  return 0;                                    
}
```

At this point, it looks like we have everything we need. Let's throw it together in a simple `Makefile` and see if it builds.


```makefile
CC=gcc
CFLAGS=-fPIC -Os -fno-stack-protector -ggdb
AS=as
LD=ld
LDFLAGS=--gc-sections

LINK_ORDER=start.o plat_iface.o hello.o

all:
        $(CC) -o hello.o $(CFLAGS) -c hello.c
        $(AS) -o plat_iface.o plat_iface.s
        $(AS) -o start.o start.s
        $(LD) -o hello.elf $(LDFLAGS) $(LINK_ORDER) -T elf.ld
        $(LD) -o hello.bin $(LDFLAGS) $(LINK_ORDER) -T binary2.ld --oformat=binary

clean:
        rm *.o *.elf *.bin
```

This Makefile requires a simple linker script called elf.ld, which is below.

```
ENTRY(start_external)

SECTIONS
{
  . = 0x42000;
  .text : { *(.text) }
  . = 0x690000;
  .data : { *(.data) }
  .bss : { *(.bss) }
}

```

Okay, so after building all of this we have an elf and a bin file containing the same code. I like having the project build the ELF as well, for easier debugging. (`-ggdb` flag actually works on the elf and gdb works as expected)

Run the code in the shellcode runner from last time. Try invoking it in python or calling it from one of those oldschool style shellcode cradles (extra credit if you can tell me why those all segfault now.)

You might want to stop here and try and identify some of the difficulties we will be addressing in the next post. Those will be below the following image of Apollo, in case you don't want any spoilers.


![](/images/netsec.png)

## Spoiler Section

Issues to address:

* Allocating memory
* Resolving and calling into library functions
* Can we have more than one "exported function"?


Tune in next time to find out!
