# bof

Nana told me that buffer overflow is one of the most common software vulnerability. 
Is that true?


ssh bof@pwnable.kr -p2222 (pw: guest)

- check contents
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
        strcpy(buf, input);
    }
    ```
    - if we were to input 'AAAAAAAAAAAA', since buf can only hold 8 bytes, it would store the first 8. But what happens to last 4?
    - after running the program with the input we find that suddenly, n=0x41414141
    - 0x41 in ascii == 'A', so that's what happens to the last 4 'A's
    - i copied bof.c into my personal environment and created my own executable 'test' since bof runs over nc
    - when i run gdb test i disassemble both main and func to see how it runs and look for possible breakpoints
