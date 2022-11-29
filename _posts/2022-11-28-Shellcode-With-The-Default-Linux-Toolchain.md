---
layout: post
title: Offensive Tool Development - The Shellcode Compiler Was Right There All Along... (Part 1)
---
*TLDR; Linker scripts can be used to generate shellcode in a fairly platform agnostic way. This allows offensive developers to use the full capibilities of the Linux Toolchain, sans library code (until a dynamic loader for library calls can be devised)*


# What we will be studying with this series
* Shellcode Generation with `gcc`, `ld`, and `as`.
