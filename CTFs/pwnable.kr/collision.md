# Collision

Daddy told me about cool MD5 hash collision today.
I wanna do something like that too!

ssh col@pwnable.kr -p2222 (pw:guest)

- upon ssh'ing, we check the contents of the current folder
```bash
col@ubuntu:~$ ls -ls
total 24
16 -r-xr-sr-x 1 root col_pwn 15164 Mar 26  2025 col
 4 -rw-r--r-- 1 root root      589 Mar 26  2025 col.c
 4 -r--r----- 1 root col_pwn    26 Apr  2 08:58 flag
```
- we have to get the contents of flag, lets check col.c

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                setregid(getegid(), getegid());
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```
- what particularly stands out are:
```c
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}
```
and
```c
if(hashcode == check_password( argv[1] ))
```
- lets run the program to see the inputs
```bash
col@ubuntu:~$ ./col a
passcode length should be 20 bytes
col@ubuntu:~$ ./col aaaaaaaaaaaaaaaaaaaa
wrong passcode.
col@ubuntu:~$
```
- going back to how the password is determined, it is done in the check_password(const char* p) function
    - from what I can understand, it casts int* onto char*
    - because integers are 4 bytes compared to chars being 1 byte, each int* contains 4 chars
    ```
    if we start with 'aaaaaaaaaaaaaaaaaaaa'
    int* will index it like:
    'aaaa aaaa aaaa aaaa aaaa'
    essentially we turn 20 chars into an array 5 ints
    ```
    - now that we know this, the next lines of code make sense
    ```c
    for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
    ```
    - it takes each int from the array and adds them
    - in main it compares it to the hashcode 0x21DD09EC
    ```c
    if(hashcode == check_password( argv[1] ))
    ```
    - using this info, my intuition says that we need to input 5 integers that add up to the hashcode
    - here's an example of how this would work
    ```
    aaaaaaaaaaaaaaaaaaaa => aaaa aaaa aaaa aaaa aaaa
    but this also equals
    0x61616161 0x61616161 0x61616161 0x61616161 0x61616161
    if we add all these up it would equal 1E6E6E6E5
    ```
    - one thing to note is that we cannot use characters like 0x00 because the computer will interpret that as the end of a string and cut the input there
    - an idea is to make the first 4 integers the same and add what ever number is needed for the last integer
    ```
    01010101 01010101 01010101 01010101 1dd905e8

    adding all these together would equal the desired hashcode: 21dd09ec
    ```
    ```bash
    col@ubuntu:~$ ./col "$(printf '\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x1d\xd9\x05\xe8')"
    wrong passcode.
    ```
    - at first this doesnt make sense
        - things to note is that the computer recognizes this as 20 bytes so thats a plus
        - the explanation: x86 architecture is little endian, meaning that when a multibyte number is stored in memory, it is stored with its least significant byte first
    ```
    in this case, when we type:
    010101010101010101010101010101011dd905e8

    when the program casts it onto an int*, it makes it so that each index is 4 bytes instead of 1
    if we (human) separated every 4 bytes (8 characters), we would probably separate it like this:
    01010101 01010101 01010101 01010101 1dd905e8

    but on x86 architecture with the little-endian convention, the computer converts the char* to int* and stores it like this

    01010101 01010101 01010101 01010101 e805d91d

    where the bytes are reversed since multibyte numbers are stored in memory with the least significant byte first
    The reason it isn't stored like that when it's a char* is because chars are not multibyte. It changes to this format when int* is cast onto it because the indices become multibyte
    ```
    ```bash
    col@ubuntu:~$ ./col "$(printf '\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\xe8\x05\xd9\x1d')"
    Two_hash_collision_Nicely
    col@ubuntu:~$
    ```
    nice