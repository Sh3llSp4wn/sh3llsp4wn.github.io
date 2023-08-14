---
layout: post
title: Offensive Tool Development - The Shellcode Compiler Was Right There All Along... (Part 2)
---

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

It's time for a quick lesson on the steps used by the toolchain to create the output binary. There are three standard steps. These steps are as follows.

* Lexical Processing
* Compilation
* Linking
