---
layout: post
title: Offensive Tool Development - The Shellcode Compiler Was Right There All Along... (Part 1)
---
*TLDR; Linker scripts can be used to generate shellcode via C in a fairly platform agnostic way. This allows offensive developers to use the full capabilities of the Linux Toolchain, sans library code (until a dynamic loader for library calls can be devised)*


# What we will be studying with this series
* Shellcode Generation with `gcc`, `ld`, and `as`.


## Preliminaries

This article will assume the following of the reader:


1. A passing familiarity with C programming and Assembly Language
2. An understanding of Linux CLI environment
3. Some knowledge of Operating System boot processes
4. Some knowledge of exploitation principles
  * Having heard of the steps in a basic buffer overflow, for example


This article will also go into a lot of "lemmas" or diatribes about small technical details surrounding this process. That is to say, you do not need to understand everything on your first reading. For the main points I will attempt to be clear and annotate them as important, but I can not promise this notation will be consistent. 

Lets begin!

## Shellcode Compilers

What is the goal here? What do we mean as shellcode?

For our purposes: *shellcode* is a chunk of position independent code that is executed in a "remote execution context". Here a remote execution context could be "in the stack of a poorly written HTTP server", or in a remote process via a remote access tool, or even something that runs once the userspace-kernelspace boundary is crossed via an LPE. This section needs no motivation. The ability to create these chunks of code is obviously very useful in a offensive development context.


That being said, the process of creating these chunks of code is extremely non-trivial. There are a number of techniques to generate these, and they will be discussed below. If you don't care, please skip to the section called: `But wait, how are bootloaders compiled`



### Classic Shellcode Technique: The Good Ol' Assembler

A classic technique for the creation of shellcode is, in effect, The most direct possible way. Just writing it in direct assembly and assembling it with the options to output the raw instructions. The details are easier to deliver via example, so we will go through the basic "hello world" example in shellcode. This requires using interfaces that the compiler does not typically expose to programmers. So, for our example, we will emulate the following C code in assembly.

```c

static char* msg = "Hello, Friend\n";

int main(){
  int size = write(1, msg, sizeof(msg));
  return 0;
}

```

Upon disassembly this c program uses the `write` wrapper provided by the OS standard library. These eventually resolve to the actual `write` syscall, but not without significant layers of abstraction and error checking. (In most standard library implementations these `syscall` like interfaces provide a clean interface for extracting error conditions via the `errno` pattern. This constitutes a large amount of the code the standard library provides - in addition to the call to the actual syscall interface itself.).
![](/images/main_dis.png)

So, lets look at what this imported `write` looks like.

![](/images/write_dis.png)

Soo, all this extra code just to do this small pattern...

![](/images/write_syscall.png)

To call kernel functions from userspace, Linux provides a Application Binary Interface called the Linux ABI. This ABI is used by loading a specific set of registers with the callee function arguments and this loading the `A` register with a specific `syscall` number and then invoking a userspace interrupt. In 32-bit x86 this was `int 0x80`, and in x86\_64 this interrupt is called via the `syscall` instruction.

We can see in the above screenshot the Linux ABI registers being loaded via various stack arguments and registers. Once `syscall` is executed the AX value is overwritten by the return value of the syscall. The x86\_64 ABI argument registers are as follows:

```python
reg_seq = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
```

These registers are loaded with argument 1 in `rdi`, argument 2 in `rsi`, and etc etc. They often are loaded backwards in assembly language. This convention is preserved from 32-bit x86 assembly where arguments were pushed to the stack "from right to left" which is to say where the last argument is pushed on the stack first. This is why, often, in 64-bit x86 assembly (which does it's first arguments via registers) the registers are set up in "reverse" order, even though the registers can be set up in a totally arbitrary order.

What follows is our x86\_64 `write` shellcode:

```nasm
section .text
bits 64
global _start
SYS_write equ 1

_start:
  mov rax, SYS_write
  mov rdi, 1
  lea rsi, [rel msg]
  mov rdx, msglen
  syscall
  ret

msg db "hello, friend",0xa,0
msglen equ $-msg
```

This, when compiled via the following command; `nasm shellcode.s` creates a small `shellcode` binary that is just the compiled instructions we specified. 

![](/images/hexdump_write_shellcode.png)
![](/images/write_shellcode_disassembly.png)

The only reason this code we wrote is position independent is because we forced it to be via the `rel` directive in the `lea` instruction. This causes the assembler to output `IP` relative instructions. Otherwise the assembler will spit out code that tries to load the address `0x19` instead of `[rip + 0x19]`. This can cause... issues. 

Knowing and remembering all the things that could possibly be relative in shellcode is a significant difficulty in it's creation. That being said, we are not at the complaining step yet. So, lets continue with this example.

Also, knowing that this is an extremely trivial example, further shows how non-portable and time consuming this variant of shellcode generation can be. Creating a corpus of configurable shellcode binaries such as in the `Metasploit Framework` was an enormous effort that has been crystallized in hacker history. 


We'll save off this `shellcode` file to test in a moment once we have generated some other examples. 


### Slightly Less Classic Shellcode Technique: pwntools shellcode generators

`pwntools` provides a set of chainable generators that output limited set of pre-compiled chunks of shellcode that can be configured. This method is also really useful if you are generating shellcode for platforms that you are not intimately familiar with.

Let's put together the same `write` example. 

```python
from pwn import *
context.arch = 'amd64'

msg = "hello, friend\n"
sc = shellcraft.amd64.write(1, msg, len(msg))

with open("shellcode.pwn", "wb") as f:
  f.write(asm(sc))

print("OK")
```

As you can see, the operative portion of this shellcode generator is the call to `shellcraft.amd64.write`. The process that `pwntools` uses to generate this shellcode from the `write` syscall is similar to our previous example with portions of the `.s/.asm` file being constructed by `pwntools` when `shellcraft` is invoked. The call to the `asm()` function actually invokes the assembler on this generated assembly. Internally `pwntools` uses some elements of the gnu binutils programs to extract the built shellcode from the binary created by the gnu assembler (`gas`). The `asm` files define a special section called `.shellcode` which contains the assembled template code. This section is then copied out of the created binary via the `objcopy` program and then returned to the user as binary data.


### Even more obscure shellcode technique: radare2 egg compiler


### A Debuggable Shellcode Tester


## Bootloaders

Now that we've discussed current shellcode generation strategies, lets take a brief aside on bootloaders. Why? We'll get to that.


