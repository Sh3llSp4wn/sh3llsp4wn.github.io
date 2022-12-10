---
layout: post
title: Offensive Tool Development - The Shellcode Compiler Was Right There All Along... (Part 1)
---
*TLDR; Linker scripts can be used to generate shellcode in a fairly platform agnostic way. This allows offensive developers to use the full capibilities of the Linux Toolchain, sans library code (until a dynamic loader for library calls can be devised)*


# What we will be studying with this series
* Shellcode Generation with `gcc`, `ld`, and `as`.


## Preliminaries

This article will asume the following of the reader:


1. A passing familiarity with C programming
2. An understanding of Linux CLI environment
3. Some knowledge of Operating System boot processes
4. Some knowledge of exploitation principles
  * Having heard of the steps in a basic buffer overflow, for example


This article will also go into a lot of "lemmas" or diatribes about small technical details surrounding this process. That is to say, you do not need to understand everything on your first reading. For the main points I will attempt to be clear and anotate them as important, but I can not promise this notation will be consistant. 

Lets begin!

## Shellcode Compilers

What is the goal here? What do we mean as shellcode?

For our purposes: *shellcode* is a chunk of position independent code that is executed in a "remote execution context". Here a remote execution context could be "in the stack of a poorly written HTTP server", or in a remote process via a remote access tool, or even something that runs once the userspace-kernelspace boundry is crossed via an LPE. This section needs no motivation. The ability to create these chunks of code is obviously very useful in a offensive development context.


That being said, the process of creating these chunks of code is extreamly non-trivial. There are a number of techniques to generate these, and they will be discussed below. If you don't care, please skip to the section called: `But wait, how are bootloaders compiled`



### Classic Shellcode Technique: The Good Ol' Assembler

A classic technique for the creation of shellcode is, in effect, using xxd to rip out the `.text` section from a compiled ELF. The details are easier to deliver via example, so we will go through a basic "hello world" in shellcode. This requires using interfaces that the compiler does not typically expose to programmers. So for our example, we will emulate the following C code in assembely "language".

```C

static char* msg = "Hello, Friend\n";

int main(){
  int size = write(1, msg, sizeof(msg));
  return 0;
}

```

Upon disassembly this c program uses the `write` wrapper provided by the compiler's standard library. These eventually resolve to the actual `write` syscall, but not without some layers of abstraction and error checking. (In most standard library implementations these `syscall` like interfaces provide a clean interface for extracting error conditions via the `errno` pattern. This constitutes a large amount of the code the standard library provides in addition to the call to the actual syscall interface itself.)

![](assets/images/main_dis.png)

So, lets look at what this imported `write` looks like.

![](assets/images/write_dis.png)

Soo, all this extra code just to do this small pattern...

![](assets/images/write_syscall.png)


### Slightly Less Clasic Shellcode Technique: pwntools shellcode generators


### Even more obscure shellcode technique: radare2 egg compiler


## Bootloaders

Now that we've discussed current shellcode generation strategies, lets take a brief asside on bootloaders. Why? We'll get to that.


