# Random
Daddy, teach me how to use random value in programming!

ssh random@pwnable.kr -p2222 (pw:guest)

- first, lets check the directory
```bash
random@ubuntu:~$ ls -ls
total 24
 4 -r--r----- 1 root random_pwn    34 Apr  5 09:45 flag
16 -r-xr-sr-x 1 root random_pwn 16232 Apr  5 09:49 random
 4 -rw-r--r-- 1 root root         335 Apr  5 09:49 random.c
random@ubuntu:~$ 
```
and we check the random.c file
```c
#include <stdio.h>

int main(){
        unsigned int random;
        random = rand();        // random value!

        unsigned int key=0;
        scanf("%d", &key);

        if( (key ^ random) == 0xcafebabe ){
                printf("Good!\n");
                setregid(getegid(), getegid());
                system("/bin/cat flag");
                return 0;
        }

        printf("Wrong, maybe you should try 2^32 cases.\n");
        return 0;
}
```
- my first thoughts, random number generators are never truly random, so there must be values that are uniform in some way
- lets disassemble the binary
```bash
0000000000001209 <main>:
    1209:       f3 0f 1e fa             endbr64 
    120d:       55                      push   %rbp
    120e:       48 89 e5                mov    %rsp,%rbp
    1211:       53                      push   %rbx
    1212:       48 83 ec 18             sub    $0x18,%rsp
    1216:       64 48 8b 04 25 28 00    mov    %fs:0x28,%rax
    121d:       00 00 
    121f:       48 89 45 e8             mov    %rax,-0x18(%rbp)
    1223:       31 c0                   xor    %eax,%eax
    1225:       b8 00 00 00 00          mov    $0x0,%eax
    122a:       e8 e1 fe ff ff          call   1110 <rand@plt>
    122f:       89 45 e4                mov    %eax,-0x1c(%rbp)
    1232:       c7 45 e0 00 00 00 00    movl   $0x0,-0x20(%rbp)
    1239:       48 8d 45 e0             lea    -0x20(%rbp),%rax
    123d:       48 89 c6                mov    %rax,%rsi
    1240:       48 8d 05 c1 0d 00 00    lea    0xdc1(%rip),%rax        # 2008 <_IO_stdin_used+0x8>
    1247:       48 89 c7                mov    %rax,%rdi
    124a:       b8 00 00 00 00          mov    $0x0,%eax
    124f:       e8 ac fe ff ff          call   1100 <__isoc99_scanf@plt>
    1254:       8b 45 e0                mov    -0x20(%rbp),%eax
    1257:       33 45 e4                xor    -0x1c(%rbp),%eax
    125a:       3d be ba fe ca          cmp    $0xcafebabe,%eax
    125f:       75 4e                   jne    12af <main+0xa6>
    1261:       48 8d 05 a3 0d 00 00    lea    0xda3(%rip),%rax        # 200b <_IO_stdin_used+0xb>
    1268:       48 89 c7                mov    %rax,%rdi
    126b:       e8 40 fe ff ff          call   10b0 <puts@plt>
    1270:       b8 00 00 00 00          mov    $0x0,%eax
    1275:       e8 66 fe ff ff          call   10e0 <getegid@plt>
    127a:       89 c3                   mov    %eax,%ebx
    127c:       b8 00 00 00 00          mov    $0x0,%eax
    1281:       e8 5a fe ff ff          call   10e0 <getegid@plt>
    1286:       89 de                   mov    %ebx,%esi
    1288:       89 c7                   mov    %eax,%edi
    128a:       b8 00 00 00 00          mov    $0x0,%eax
    128f:       e8 5c fe ff ff          call   10f0 <setregid@plt>
    1294:       48 8d 05 76 0d 00 00    lea    0xd76(%rip),%rax        # 2011 <_IO_stdin_used+0x11>
    129b:       48 89 c7                mov    %rax,%rdi
    129e:       b8 00 00 00 00          mov    $0x0,%eax
    12a3:       e8 28 fe ff ff          call   10d0 <system@plt>
    12a8:       b8 00 00 00 00          mov    $0x0,%eax
    12ad:       eb 14                   jmp    12c3 <main+0xba>
    12af:       48 8d 05 6a 0d 00 00    lea    0xd6a(%rip),%rax        # 2020 <_IO_stdin_used+0x20>
    12b6:       48 89 c7                mov    %rax,%rdi
    12b9:       e8 f2 fd ff ff          call   10b0 <puts@plt>
    12be:       b8 00 00 00 00          mov    $0x0,%eax
    12c3:       48 8b 55 e8             mov    -0x18(%rbp),%rdx
    12c7:       64 48 2b 14 25 28 00    sub    %fs:0x28,%rdx
    12ce:       00 00 
    12d0:       74 05                   je     12d7 <main+0xce>
    12d2:       e8 e9 fd ff ff          call   10c0 <__stack_chk_fail@plt>
    12d7:       48 8b 5d f8             mov    -0x8(%rbp),%rbx
    12db:       c9                      leave  
    12dc:       c3                      ret 
```
- ok so the unsigned integer variable random is stored -0x1c(%rbp)
- lets run gdb twice and see what the random values are
    - I will put a breakpoint right after the call to rand()
- both times we got this output
```bash
   0x5640d412d22f <main+38>    mov    dword ptr [rbp - 0x1c], eax     [0x7ffd4af44064] <= 0x6b8b4567
 ► 0x5640d412d232 <main+41>    mov    dword ptr [rbp - 0x20], 0       [0x7ffd4af44060] <= 0
   0x5640d412d239 <main+48>    lea    rax, [rbp - 0x20]
   0x5640d412d23d <main+52>    mov    rsi, rax
   0x5640d412d240 <main+55>    lea    rax, [rip + 0xdc1]              RAX => 0x5640d412e008 ◂— 0x21646f6f47006425 /* '%d' */
   0x5640d412d247 <main+62>    mov    rdi, rax
   0x5640d412d24a <main+65>    mov    eax, 0                          EAX => 0
   0x5640d412d24f <main+70>    call   __isoc99_scanf@plt          <__isoc99_scanf@plt>
 
   0x5640d412d254 <main+75>    mov    eax, dword ptr [rbp - 0x20]
   0x5640d412d257 <main+78>    xor    eax, dword ptr [rbp - 0x1c]
   0x5640d412d25a <main+81>    cmp    eax, 0xcafebabe
─────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────
00:0000│ rsp 0x7ffd4af44060 ◂— 0x6b8b456700000000
01:0008│-018 0x7ffd4af44068 ◂— 0x6d229f9b93e50200
02:0010│-010 0x7ffd4af44070 ◂— 0
03:0018│-008 0x7ffd4af44078 ◂— 0
04:0020│ rbp 0x7ffd4af44080 ◂— 1
05:0028│+008 0x7ffd4af44088 —▸ 0x7f6267691d90 (__libc_start_call_main+128) ◂— mov edi, eax
06:0030│+010 0x7ffd4af44090 ◂— 0
07:0038│+018 0x7ffd4af44098 —▸ 0x5640d412d209 (main) ◂— endbr64 
───────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────
 ► 0   0x5640d412d232 main+41
   1   0x7f6267691d90 __libc_start_call_main+128
   2   0x7f6267691e40 __libc_start_main+128
   3   0x5640d412d145 _start+37
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/1wx $rbp-0x1c
0x7ffd4af44064: 0x6b8b4567
```
- so our random value is 0x6b8b4567
- to get the correct input we need to solve for 0x6b8b4567 $\oplus$ 0xcafebabe = 0xa175ffd9
- since scanf will write to the variable 'key' which is an unsigned int, we need to convert 0xa175ffd9 = 2708864985
```bash
random@ubuntu:~$ ./random
2708864985
Good!
m0mmy_I_can_predict_rand0m_v4lue!
random@ubuntu:~$ 
```