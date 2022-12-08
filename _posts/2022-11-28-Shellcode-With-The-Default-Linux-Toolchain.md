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

Main looks like the following:

```
[0x00001650]> s main 
[0x000019a0]> pdf
            ; CALL XREF from entry0 @ 0x178d(x)
/ 78: int main (int argc, char **argv, char **envp);
|           ; var int64_t var_ch @ rbp-0xc
|           ; var int64_t var_10h @ rbp-0x10
|           0x000019a0      4c8b1d611100.  mov r11, qword [obj.__retguard_2628] ; [0x2b08:8]=0
|           0x000019a7      4c331c24       xor r11, qword [rsp]
|           0x000019ab      55             push rbp
|           0x000019ac      4889e5         mov rbp, rsp
|           0x000019af      4153           push r11
|           0x000019b1      50             push rax
|           0x000019b2      c745f4000000.  mov dword [var_ch], 0
|           0x000019b9      488b35e82200.  mov rsi, qword [obj.msg]    ; [0x3ca8:8]=0
|           0x000019c0      bf01000000     mov edi, 1
|           0x000019c5      ba08000000     mov edx, 8
|           0x000019ca      e8f1000000     call fcn.00001ac0
|           0x000019cf      8945f0         mov dword [var_10h], eax
|           0x000019d2      31c0           xor eax, eax
|           0x000019d4      4883c408       add rsp, 8
|           0x000019d8      415b           pop r11
|           0x000019da      5d             pop rbp
|           0x000019db      4c331c24       xor r11, qword [rsp]
|           0x000019df      4c3b1d221100.  cmp r11, qword [obj.__retguard_2628] ; [0x2b08:8]=0
|       ,=< 0x000019e6      0f8403000000   je 0x19ef
|       |   0x000019ec      cc             int3
..
|       |   ; CODE XREF from main @ 0x19e6(x)
\       `-> 0x000019ef      c3             ret
[0x000019a0]> 
```

Side Note: The first person to DM me on Twitter what operating system this disassembly is from and why is owed a beer by me.

We see the main function call in main goes to `fcn.00001ac0` the following is it's disassembly

```
[0x000019a0]> s fcn.00001ac0 
[0x00001ac0]> pdf
        :   ; CALL XREF from main @ 0x19ca(x)
/ 17: fcn.00001ac0 ();
|       :   0x00001ac0      4c8b1dd91100.  mov r11, qword [reloc.write] ; [0x2ca0:8]=0x1ad1
|       :   0x00001ac7  ~   e864ffffff     call fcn.00001a30
|       :   ;-- write:
..
\       `=< 0x00001acc      e951ffffff     jmp 0x1a22                  ; fcn.000017e0+0x242
```

This appears to just call some function and then explicitly jump to `0x1a22`. The function is uninteresting, so let's look at the explicit jump location. 


```
[0x00001a30]> s 0x1a22
[0x00001a22]> pdf
            ; CALL XREF from sym.__init @ 0x19f4(x)
/ 245: fcn.000017e0 ();
|           0x000017e0      4c8b1d111300.  mov r11, qword [obj.__retguard_1471] ; [0x2af8:8]=0
|           0x000017e7      4c331c24       xor r11, qword [rsp]
|           0x000017eb      55             push rbp
|           0x000017ec      4889e5         mov rbp, rsp
|           0x000017ef      4153           push r11
|           0x000017f1      4157           push r15
|           0x000017f3      4156           push r14
|           0x000017f5      4154           push r12
|           0x000017f7      803dba240000.  cmp byte [0x00003cb8], 0    ; [0x3cb8:1]=0
|       ,=< 0x000017fe      7420           je 0x1820
|       |   0x00001800      415c           pop r12
|       |   0x00001802      415e           pop r14
|       |   0x00001804      415f           pop r15
|       |   0x00001806      415b           pop r11
|       |   0x00001808      5d             pop rbp
|       |   0x00001809      4c331c24       xor r11, qword [rsp]
|       |   0x0000180d      4c3b1de41200.  cmp r11, qword [obj.__retguard_1471] ; [0x2af8:8]=0
|      ,==< 0x00001814      7409           je 0x181f
|      ||   0x00001816      cc             int3
..
|      ||   ; CODE XREF from fcn.000017e0 @ 0x1814(x)
|      `--> 0x0000181f      c3             ret
|       |   ; CODE XREF from fcn.000017e0 @ 0x17fe(x)
|       `-> 0x00001820      c60591240000.  mov byte [0x00003cb8], 1    ; [0x3cb8:1]=0
|           0x00001827      488d3d3aedff.  lea rdi, section..eh_frame  ; 0x568
|           0x0000182e      488d358b2400.  lea rsi, [0x00003cc0]
|           0x00001835      e886ffffff     call sym.__register_frame_info
|           0x0000183a      48833dce1200.  cmp qword [section..jcr], 0 ; [0x2b10:8]=0
|       ,=< 0x00001842      7416           je 0x185a
|       |   0x00001844      48833d0c1400.  cmp qword [section..got], 0 ; [0x2c58:8]=0
|      ,==< 0x0000184c      740c           je 0x185a
|      ||   0x0000184e      488d3dbb1200.  lea rdi, section..jcr       ; 0x2b10
|      ||   0x00001855      e826020000     call fcn.00001a80
|      ||   ; CODE XREFS from fcn.000017e0 @ 0x1842(x), 0x184c(x)
|      ``-> 0x0000185a      4c8b35b71200.  mov r14, qword [section..ctors] ; [0x2b18:8]=-1
|           0x00001861      4983feff       cmp r14, 0xffffffffffffffff
|       ,=< 0x00001865      7528           jne 0x188f
|       |   0x00001867      48c7c1ffffff.  mov rcx, 0xffffffffffffffff
|       |   0x0000186e      488d05a31200.  lea rax, section..ctors     ; 0x2b18
|      ,==< 0x00001875      eb09           jmp 0x1880
..
|      ||   ; CODE XREFS from fcn.000017e0 @ 0x1875(x), 0x188d(x)
|     .`--> 0x00001880      4c8d7101       lea r14, [rcx + 1]
|     : |   0x00001884      48837cc81000   cmp qword [rax + rcx*8 + 0x10], 0
|     : |   0x0000188a      4c89f1         mov rcx, r14
|     `===< 0x0000188d      75f1           jne 0x1880
|       |   ; CODE XREF from fcn.000017e0 @ 0x1865(x)
|       `-> 0x0000188f      4d85f6         test r14, r14
|       ,=< 0x00001892      742e           je 0x18c2
|       |   0x00001894      488d057d1200.  lea rax, section..ctors     ; 0x2b18
|       |   0x0000189b      4e8d3cf0       lea r15, [rax + r14*8]
|       |   0x0000189f      49f7de         neg r14
|       |   0x000018a2      4531e4         xor r12d, r12d
|      ,==< 0x000018a5      eb09           jmp 0x18b0
..
|      ||   ; CODE XREFS from fcn.000017e0 @ 0x18a5(x), 0x18c0(x)
|     .`--> 0x000018b0      4f8b1ce7       mov r11, qword [r15 + r12*8]
|     : |   0x000018b4      e8e7feffff     call sym.__llvm_retpoline_r11
|     : |   0x000018b9      4983c4ff       add r12, 0xffffffffffffffff
|     : |   0x000018bd      4d39e6         cmp r14, r12
|     `===< 0x000018c0      75ee           jne 0x18b0
|       |   ; CODE XREF from fcn.000017e0 @ 0x1892(x)
|       `-> 0x000018c2      488b3d971300.  mov rdi, qword [0x00002c60] ; [0x2c60:8]=0
|           0x000018c9      415c           pop r12
|           0x000018cb      415e           pop r14
|           0x000018cd      415f           pop r15
|           0x000018cf      415b           pop r11
|           0x000018d1      5d             pop rbp
|       ,=< 0x000018d2      e9c9010000     jmp 0x1aa0
..
        |   ; CALL XREF from sym.__fini @ 0x1a04(x)
|    ||||   ; CODE XREFS from fcn.000018e0 @ 0x191d(x), 0x192f(x)
|     |||   ; CODE XREF from fcn.000018e0 @ 0x1914(x)
|   |||||   ; CODE XREFS from fcn.000018e0 @ 0x196a(x), 0x197e(x)
|    ||||   ; CODE XREFS from fcn.000018e0 @ 0x18fd(x), 0x1938(x), 0x195d(x)
|      ||   ; CODE XREF from fcn.000018e0 @ 0x1996(x)
        |   ; CALL XREF from entry0 @ 0x178d(x)
|      ||   ; CODE XREF from main @ 0x19e6(x)
        |   ;-- section..init:
        |   ; CALL XREF from entry0 @ 0x177f(x)
        |   ;-- section..fini:
        |   ;-- section..plt:
        |   ; CODE XREF from sym.imp._csu_finish @ +0xb(x)
        |   ; CODE XREF from sym.imp.exit @ +0xb(x)
        |   ; CODE XREF from loc.imp._Jv_RegisterClasses @ +0xb(x)
        |   ; CODE XREF from sym.imp.atexit @ +0xb(x)
|    :::|   ; XREFS: CODE 0x00001a27  CODE 0x00001a4c  CODE 0x00001a6c  CODE 0x00001a8c  CODE 0x00001aac  CODE 0x00001acc  
| ...-----> 0x00001a22      f390           pause                       ; [15] -r-x section size 208 named .plt
| ::::::|   0x00001a24      0faee8         lfence
| ========< 0x00001a27      ebf9           jmp 0x1a22
..
  ::::::|   ; XREFS: CALL 0x00001a1d  CALL 0x00001a47  CALL 0x00001a67  CALL 0x00001a87  CALL 0x00001aa7  CALL 0x00001ac7  
  ::::::|   ; CALL XREF from entry0 @ 0x1693(x)
  ::: ::|   ; CALL XREF from entry0 @ 0x1794(x)
   ::  :|   ; CALL XREF from fcn.000017e0 @ 0x1855(x)
|   :   |   ; CODE XREF from fcn.000017e0 @ 0x18d2(x)
|   :   `-> 0x00001aa0      4c8b1df11100.  mov r11, qword [reloc.atexit] ; [0x2c98:8]=0x1ab1
|   :       0x00001aa7  ~   e884ffffff     call fcn.00001a30
|   :       ;-- atexit:
..
\   `=====< 0x00001aac      e971ffffff     jmp 0x1a22
```

Yeah, so that was pretty gross and uninteresting, but it shows my point. This is not the pure syscall interface, it's a wrapper.

What does a standard invocation of the write syscall look like?

```asm
mov rax, 1
syscall
```

The linux ABI registers need to be set up to point at the correct file descriptor (1) and a `lea` is needed to load the address of the string, but those are somewhat unimportant details when it comes to how this syscall is wrapped by the standard library. This example, hopefully, shows that the standard library calling of these functions are too large to be used as shellcode. 

### Slightly Less Clasic Shellcode Technique: pwntools shellcode generators


### Even more obscure shellcode technique: radare2 egg compiler


## Bootloaders

Now that we've discussed current shellcode generation strategies, lets take a brief asside on bootloaders. Why? We'll get to that.


