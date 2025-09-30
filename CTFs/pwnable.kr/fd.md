# fd
Mommy! what is a file descriptor in Linux?

* try to play the wargame your self but if you are ABSOLUTE beginner, follow this tutorial link:
https://youtu.be/971eZhMHQQw

ssh fd@pwnable.kr -p2222 (pw:guest)

- upon ssh'ing into the server I immediatly look into the contents
```bash
fd@ubuntu:~$ ls -ls
total 24
16 -r-xr-sr-x 1 root fd_pwn 15148 Mar 26  2025 fd
 4 -rw-r--r-- 1 root root     452 Mar 26  2025 fd.c
 4 -r--r----- 1 root fd_pwn    50 Apr  1 06:06 flag
```
- I understand that I am supposed to get the contents of flag but I have no permissions to open it
- when I check fd.c I find this:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                setregid(getegid(), getegid());
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}
```
- from what I can understand, the program takes in my first argument as a file descriptor to read from
    - more specifically, the file descriptor to read from is my first argument minus the hex number 0x1234
- It then reads 32 bytes from the file descriptor - if the string is "LETMEWIN", it'll display the contents of the flag file
- my intuition says that the file descriptor that would let me input the "LETMEWIN" string is stdin or 0, since I can type the answer on the commandline
- this means we need argv[1] to equal 0x1234
```bash
fd@ubuntu:~$ ./fd $((0x1234))
LETMEWIN
good job :)
Mama! Now_I_understand_what_file_descriptors_are!
```