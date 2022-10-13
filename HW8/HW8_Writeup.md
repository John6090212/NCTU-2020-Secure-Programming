###### tags: `程式安全`
# Secure Programming HW8 Writeup
## wishMachine
### 解法
先file看一下確定是在linux上面跑
跑一下發現是要輸入coin序號的題目
接著用gdb跑，結果程式直接結束了!

一定是程式裡面有搞鬼，透過IDA來找到搞鬼的function在哪
因為程式會印Welcom to the wish machine，直接在IDA用search text就可以找到該data，再data右鍵選Xrefs graph to就可以看到使用該data的function為sub_400B8D

查看sub_400B8D可以發現印完三個一開始的歡迎訊息後，會呼叫ptrace，如果ptrace的回傳值為-1就會呼叫sub_40F130
sub_40F130裡面會呼叫_run_exit_handlers，這應該就是會害程式執行結束的function
覺得ptrace有點眼熟就去爬文，結果發現ptrace就是gdb用來對程式進行操作會使用的function
也就是說如果程式呼叫ptrace，然後參數使用PTRACE_TRACEME，發現回傳值為-1就代表有人正在debug它，就會直接結束
那就把回傳值改成0就可以完美迴避了，改成0之後gdb果然跳出了要求輸入coin序號的訊息，代表成功避開ptrace的陷阱

處理完ptrace後，要找到要求輸入序號的function在哪裡
吃輸入的function通常會呼叫scanf，所以直接找到scanf然後看Xrefs graph to就可以知道呼叫它的是sub_400BE6

打開sub_400BE6發現裡面有印One by one...要求輸入序號的訊息，是正確的function沒錯
直接decompile來看c code，為了比較好看，只展示重要的部份
從code可以看到for loop會跑1000次，代表序號有1000個
序號為70個char，因為scanf是吃%70s，並把輸入放進v10這個char array
接著會把你的輸入丟進sub_400E0A，再跟一個初始化好的v11一起丟進sub_400F69
```c=
for ( i = 0; i <= 999; ++i )
  {
    printf((unsigned int)"One by one, What is the serial number of coin%d ?", (unsigned int)i);
    j_memset_ifunc(v10, 0LL, 70LL);
    scanf((__int64)"%70s", v10);
    sub_400E0A((__int64)v10);
    sub_400F69((__int64)v11, (__int64)v10);
  }
  printf((unsigned int)"Ok, the flag is %s", v11, v7, v6, a5, a6);
  result = 0LL;
  if ( __readfsqword(0x28u) != v13 )
    sub_44BD80();
  return result;
```
先看sub_400F69，他會把你的輸入v10跟初始化好的v11做xor後存進v11裡面
根據sub_400BE6的c code，最後會印出的flag就是v11(printf後面的參數我修了但沒有消失QQ)，所以全部的v10輸入正確才能得到正確的flag
```c=
_BYTE *__fastcall sub_400F69(__int64 a1, __int64 a2)
{
  _BYTE *result; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 69; ++i )
  {
    result = (_BYTE *)(i + a1);
    *result ^= *(_BYTE *)(i + a2);
  }
  return result;
}
```
來看最重要的sub_400E0A
它會有跑70次的for loop，很明顯就是對序號的每個字做檢查
每次的loop會先修改一堆變數的值，最後會透過function pointer呼叫一個function
因為其他loop部份都沒做檢查，所以function pointer指到的function就是用來檢查的
```c=
__int64 __fastcall sub_400E0A(__int64 a1)
{
  __int64 result; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 69; i += dword_8A2118 )
  {
    qword_8A2108 = a1;
    dword_8A2114 = *((_DWORD *)&unk_6D5114 + 10 * dword_8A1070);
    dword_8A2118 = *((_DWORD *)&unk_6D5118 + 10 * dword_8A1070);
    dword_8A211C = *((_DWORD *)&unk_6D511C + 10 * dword_8A1070);
    dword_8A2120 = dword_6D5120[10 * dword_8A1070];
    dword_8A2110 = *((_DWORD *)&unk_6D5110 + 10 * dword_8A1070);
    qword_8A2100 = *((_QWORD *)&unk_6D5100 + 5 * dword_8A1070) + dword_8A2110;
    ((void (*)(void))qword_8A2100)();
    ++dword_8A1070;
    result = (unsigned int)dword_8A2118;
  }
  return result;
}
```
直接用gdb下斷點來看它第一次呼叫了什麼function，發現是sub_4011D6
看了算法很像fibonacci，但是把跟v1比較的正確答案撈出來卻不在fibonacci裡面！
想來想去想不通，就照著disassemble的c code寫了個c program來跑
結果v1的值overflow了＠＠，我看到v1是int的時候還以為是不會算很大==

因為序號只有大寫英文跟數字，我就用c把1-128的結果印出來(其他位置有點多餘但就順便弄了)，放進python的list來查表
0的時候v1沒初始化很危險，我就隨便塞了個0當作值，也不會用到
接著解讀正確答案如果sign bit是1要用two's complement
正確答案為(*((_DWORD *)&qword_8A2108 + i + 5))的值，拿去查表就知道正確的char是哪個
知道值之後要知道是0-69的哪個位置，位置是qword_8A2108+dword_8A2114+i，也就是v10[dword_8A2114+i]，因為sub_400E0A存進qword_8A2108的值是a1，就是sub_400E0A的參數v10

都知道就可以用有點作弊的方式，動態跑並在判斷是不是正確答案的cmp下斷點，直接用正確答案回推char[dword_8A2114+i]的值，存進python的list裡面當作coin的序號
之後強行修改register值通過判斷，透過這個過程不斷還原coin的序號
```c=
__int64 sub_4011D6()
{
  __int64 result; // rax
  int v1; // [rsp+Ch] [rbp-14h]
  int i; // [rsp+10h] [rbp-10h]
  int v3; // [rsp+14h] [rbp-Ch]
  int v4; // [rsp+18h] [rbp-8h]
  int j; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = (unsigned int)dword_8A2118;
    if ( i >= dword_8A2118 )
      break;
    v3 = 0;
    v4 = 1;
    for ( j = 0; j < *(char *)(qword_8A2108 + dword_8A2114 + i); ++j )
    {
      v1 = v3 + v4;
      v3 = v4;
      v4 = v1;
    }
    if ( v1 != *((_DWORD *)&qword_8A2108 + i + 5) )
      sub_40F130(0LL);
  }
  return result;
}
```
正當我以為結束的時候，gdb跑一跑程式突然結束了!
回去下斷點發現call的檢查function換了，這才想起來它是function pointer，逆逆真有你的
繼續挖function，下個不一樣的cal是sub_40102D
好像不是有名字的運算，不過架構跟fibonacci一樣，所以就用相同的作法
用c寫一樣的code建表->跟正確答案cmp時下斷點->查表回推序號＋修改register值硬過cmp

再下個不一樣的call是sub_401138，同sub_40102D的處理方法，但是因為值有負數，解讀正確答案sign bit為1一樣要用two's complement

再下個不一樣的call是sub_4010C8，架構換了不過更簡單了
變成不用建表，直接XOR 0x52756279就可以得到序號值，接著同上

最後一個不一樣的call是sub_400FBE，跟sub_4010C8一樣架構
只要除以135就可以得到序號值，接著同上

這樣就成功拿到第1個序號，不過有1000個，所以一定要寫腳本
使用從Going crazy還有SecureContainProtect搬過來的gdb python腳本做修改
不過我寫成了一個一次只能找一個coin序號的版本，第二次breakpoint刪起來數字會變有點麻煩 (我要寫pwn沒空改code了QQ)
所以要多包一層bash script來一次把序號找完
找完所有序號寫進檔後，再用個gdb python腳本讀檔把flag印出來

### 腳本
#### gen_serial.sh
先給bash script
內容蠻簡單，就先開個空白的finish_coin檔案，讓coin序號可以append在直接後面
之後跑0-999的for loop把所有序號寫進finish_coin檔案
arg0是指找的coin是哪個的意思

腳本跑法：
```
/bin/bash gen_serial.sh
```
```bash=
#!/bin/bash
> finish_coin
BEGIN=0
END=999
for ((i=$BEGIN; i<=$END; i++))
do
gdb --nx --batch --ex "py arg0 = $i" -x reverse.py  ./wishMachine > /dev/null
done
```
#### reverse.py
找serial number腳本
內容可以簡化成下面這樣，詳細可以看註解
1.在ptrace回傳值判斷下斷點
2.寫好序號input檔給gdb run < input用
3.執行gdb run < input
4.改ptrace回傳值過判斷
5.在scanf下斷點快速通過已經找到的coin序號
6.準備好找新的coin序號要用的斷點
7.先在sub_400E0A的斷點區域存好要用的值，例如dword_8A2114(決定index)跟dword_8A2100(決定function pointer呼叫的function)
8.在檢查function的cmp斷點透過正確答案還原序號並存到coin_list裡面，再修改register或address值通過cmp判斷
9.找到全部序號值後break，並把序號寫進finish_coin裡面

腳本跑法: 參考bash script

```python=
import gdb
import sys
import string

# list of function answer to find char
fibonacci_list = [0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181, 6765, 10946, 17711, 28657, 46368, 75025, 121393, 196418, 317811, 514229, 832040, 1346269, 2178309, 3524578, 5702887, 9227465, 14930352, 24157817, 39088169, 63245986, 102334155, 165580141, 267914296, 433494437, 701408733, 1134903170, 1836311903, -1323752223, 512559680, -811192543, -298632863, -1109825406, -1408458269, 1776683621, 368225352, 2144908973, -1781832971, 363076002, -1418756969, -1055680967, 1820529360, 764848393, -1709589543, -944741150, 1640636603, 695895453, -1958435240, -1262539787, 1073992269, -188547518, 885444751, 696897233, 1582341984, -2015728079, -433386095, 1845853122, 1412467027, -1036647147, 375819880, -660827267, -285007387, -945834654, -1230842041, 2118290601, 887448560, -1289228135, -401779575, -1691007710, -2092787285, 511172301, -1581614984, -1070442683, 1642909629, 572466946, -2079590721, -1507123775, 708252800, -798870975, -90618175, -889489150, -980107325, -1869596475, 1445263496, -424332979, 1020930517, 596597538, 1617528055, -2080841703, -463313648, 1750811945, 1287498297, -1256657054, 30841243, -1225815811, -1194974568, 1874176917, 679202349, -1741588030, -1062385681, 1490993585, 428607904, 1919601489, -1946757903, -27156414, -1973914317, -2001070731, 319982248, -1681088483, -1361106235]
sub_40102D_list = [0,11,13,24,26,37,39,50,52,63,65,76,78,89,91,102,104,115,117,128,130,141,143,154,156,167,169,180,182,193,195,206,208,219,221,232,234,245,247,258,260,271,273,284,286,297,299,310,312,323,325,336,338,349,351,362,364,375,377,388,390,401,403,414,416,427,429,440,442,453,455,466,468,479,481,492,494,505,507,518,520,531,533,544,546,557,559,570,572,583,585,596,598,609,611,622,624,635,637,648,650,661,663,674,676,687,689,700,702,713,715,726,728,739,741,752,754,765,767,778,780,791,793,804,806,817,819,830]
sub_401138_list = [-88035316,-88065916,-88066036,-88096636,-88096756,-88127356,-88127476,-88158076,-88158196,-88188796,-88188916,-88219516,-88219636,-88250236,-88250356,-88280956,-88281076,-88311676,-88311796,-88342396,-88342516,-88373116,-88373236,-88403836,-88403956,-88434556,-88434676,-88465276,-88465396,-88495996,-88496116,-88526716,-88526836,-88557436,-88557556,-88588156,-88588276,-88618876,-88618996,-88649596,-88649716,-88680316,-88680436,-88711036,-88711156,-88741756,-88741876,-88772476,-88772596,-88803196,-88803316,-88833916,-88834036,-88864636,-88864756,-88895356,-88895476,-88926076,-88926196,-88956796,-88956916,-88987516,-88987636,-89018236,-89018356,-89048956,-89049076,-89079676,-89079796,-89110396,-89110516,-89141116,-89141236,-89171836,-89171956,-89202556,-89202676,-89233276,-89233396,-89263996,-89264116,-89294716,-89294836,-89325436,-89325556,-89356156,-89356276,-89386876,-89386996,-89417596,-89417716,-89448316,-89448436,-89479036,-89479156,-89509756,-89509876,-89540476,-89540596,-89571196,-89571316,-89601916,-89602036,-89632636,-89632756,-89663356,-89663476,-89694076,-89694196,-89724796,-89724916,-89755516,-89755636,-89786236,-89786356,-89816956,-89817076,-89847676,-89847796,-89878396,-89878516,-89909116,-89909236,-89939836,-89939956,-89970556,-89970676,-90001276]

def read_reg(reg):
    return gdb.parse_and_eval("${}".format(reg))

def get_int(address):
    int_pointer = gdb.lookup_type('int').pointer()
    stack_address = gdb.Value(address)
    stack_address_pointer = stack_address.cast(int_pointer)
    val = int(stack_address_pointer.dereference())
    return val

def get_int_array(address,size):
    value = []
    for i in range(size):
        int_pointer = gdb.lookup_type('int').pointer()
        stack_address = gdb.Value(address + i*4)
        stack_address_pointer = stack_address.cast(int_pointer)
        val = int(stack_address_pointer.dereference())
        value.append(val)
    return value


def get_char(address,size):
    char_pointer = gdb.lookup_type('char').pointer()
    value = []
    for i in range(size):
        stack_address = gdb.Value(address + i)
        stack_address_pointer = stack_address.cast(char_pointer)
        val = int(hex(stack_address_pointer.dereference() & 0xff), 16)
        value.append(val)
    return value


def add_break(address):
    gdb.execute('break *{}'.format(address)) 

def twos_complement(hexstr, bits):
    value = int(hexstr, 16)
    if value & (1 << (bits-1)):
        value -= 1 << bits
    return value

if __name__ == '__main__':
    # ptrace breakpoint
    add_break(0x400BD3)
    # list to temp save coin serial number
    coin_list = [[1]*70 for i in range(1000)]
    # list of already check index in coin
    set_coin = [[False]*70 for i in range(1000)]
    # coin number to find
    finish = arg0
    # write input file for gdb run
    with open('input', 'w') as f:
        with open('finish_coin', 'r') as f_coin:
            while True:
                line = f_coin.readline()
                if line:
                    f.write(line)
                    f.write('\n')
                else:
                    break
        for i in range(finish,1000):
            for c in coin_list[i]:
                f.write(chr(c))
            f.write('\n')
    if finish:
        # breakpoint to skip already found coin
        add_break(0x400D96)
    if finish == 0:
        #dword breakpoint
        #8A2114
        add_break(0x400E51)
        #8A2118
        add_break(0x400E7B)
        #8A211C
        add_break(0x400EA5)
        #8A2120
        add_break(0x400ECF)
        #8A2100
        add_break(0x400F2F)
        #function pointer function
        #4011D6
        add_break(0x401259)
        #40102D
        add_break(0x4010A3)
        #401138
        add_break(0x4011B1)
        #4010C8
        add_break(0x401118)
        #400FBE
        add_break(0x40100D)
    gdb.execute('run < input', to_string=True)
    #change ptrace return value
    gdb.execute('set var $rax=0', to_string=True)
    gdb.execute('c', to_string=True)

    if finish:
        gdb.execute('c', to_string=True)
    # skip already found coin
    for skip in range(finish):
        if skip == finish - 1:
            gdb.execute('delete 2', to_string=True)
            #dword breakpoint
            #8A2114
            add_break(0x400E51)
            #8A2118
            add_break(0x400E7B)
            #8A211C
            add_break(0x400EA5)
            #8A2120
            add_break(0x400ECF)
            #8A2100
            add_break(0x400F2F)
            #function pointer function
            #4011D6
            add_break(0x401259)
            #40102D
            add_break(0x4010A3)
            #401138
            add_break(0x4011B1)
            #4010C8
            add_break(0x401118)
            #400FBE
            add_break(0x40100D)
        gdb.execute('c', to_string=True)
    # array base for input char[70]
    array_base = 0x7fffffffdae0
    # find coin serial number
    for coin_index in range(finish,finish+1):
        print(f"coin_index = {coin_index}", file=sys.stderr)
        for i in range(70):
            # break when all serial number is found
            if False not in set_coin[coin_index]:
                break
            # read value in sub_400E0A
            int_8A2114 = read_reg('eax')
            gdb.execute('c', to_string=True)
            int_8A2118 = read_reg('eax')
            gdb.execute('c', to_string=True)
            int_8A211C = read_reg('eax')
            gdb.execute('c', to_string=True)
            int_8A2120 = read_reg('eax')
            gdb.execute('c', to_string=True)
            int_8A2100 = read_reg('rax')

            gdb.execute('c', to_string=True)
            # for loop in function pointer function
            for j in range(int_8A2118):
                answer = 0 
                input_char = 0
                set_address = 0x0
                set_reg = False
                set_reg_name = ''
                # find correct answer, serial number char and the register or address to modify in cmp
                if int_8A2100 == 0x4011D6:
                    answer = read_reg('eax')
                    input_char = fibonacci_list.index(twos_complement(hex(answer & 0xffffffff).rstrip('L'),32))
                    set_address = read_reg('rbp')-0x14
                elif int_8A2100 == 0x40102D:
                    answer = read_reg('eax')
                    input_char = sub_40102D_list.index(answer)
                    set_address = read_reg('rbp')-0xC
                elif int_8A2100 == 0x401138:
                    answer = read_reg('eax')
                    input_char = sub_401138_list.index(twos_complement(hex(answer & 0xffffffff).rstrip('L'),32))
                    set_address = read_reg('rbp')-0xC
                elif int_8A2100 == 0x4010C8:
                    answer = read_reg('eax')
                    input_char = ord(chr(answer ^ 0x52756279))
                    set_reg = True
                    set_reg_name = 'edx'
                elif int_8A2100 == 0x400FBE:
                    answer = read_reg('edx')
                    input_char = ord(chr(answer / 135))
                    set_reg = True
                    set_reg_name = 'eax'
                
                my_answer = 0
                # save serial number char in coin list and set corresponding index in set_coin to True
                if not set_coin[coin_index][int_8A2114 + j]:
                    coin_list[coin_index][int_8A2114 +j] = input_char
                    set_coin[coin_index][int_8A2114 + j] = True
                else:
                    if set_reg:
                        my_answer = read_reg(set_reg_name)
                        #print(f"count answer = {my_answer}", file=sys.stderr)
                    else:
                        my_answer = get_int(set_address)
                        #print(f"count answer = {my_answer}", file=sys.stderr)
                # modify the value in register or address in cmp to pass check
                if set_reg:
                    gdb.execute(f"set var ${set_reg_name} = {answer}")
                else:
                    gdb.execute(f"set {{int}}{set_address} = {answer}")

                gdb.execute('c', to_string=True)
            i += int_8A2118

        #print(f'coin {coin_index} = {coin_list[coin_index]}',file=sys.stderr)

        # print coin serial number on screen
        print(''.join(map(chr,coin_list[coin_index])),file=sys.stderr)
        # write serial number to finish_coin file for next coin search
        with open('finish_coin', 'a') as f:
            for write_index in range(70):
                f.write(chr(coin_list[coin_index][write_index]))
            f.write('\n')
        
    #gdb.execute('q',to_string=True)
```
#### solve.py
拿到flag的腳本，要先有完整的finish_coin檔案，也就是要先跑完bash script
內容就過ptrace後把finish_coin裡面的序號全部丟進去，最後就會有flag

腳本跑法：
```
gdb --nx -x solve.py ./wishMachine
```
```python=
import gdb
import sys
import string

def add_break(address):
    gdb.execute('break *{}'.format(address))

if __name__ == '__main__':
    #ptrace breakpoint
    add_break(0x400BD3)

    with open('input', 'w') as f:
        with open('finish_coin', 'r') as f_coin:
            while True:
                line = f_coin.readline()
                if line:
                    f.write(line)
                    f.write('\n')
                else:
                    break
        
    gdb.execute('run < input', to_string=True)
    #change ptrace return value
    gdb.execute('set var $rax=0', to_string=True)
    gdb.execute('c', to_string=True)
    gdb.execute('q', to_string=True)
```

## SecureContainProtect
### 解法
先file一下看執行檔資訊，確認是在linux上面跑
試跑發現是數獨題目，而且每次題目都長一樣，看起來沒很好解就直接用下面這個解數獨的網站解掉
https://www.sudoku-solutions.com/
解完長這樣：
![](https://i.imgur.com/gCs4oBH.png)
之後手動輸進程式裡面，通過後會要求你輸入ACTION CODE，看起來這就是這題的核心部份
使用IDA打開程式進入main function查看，可以發現會有類似上課教的switch的CFG
檢查是輸入z也就是finish才開始，從下圖可以知道輸入z之後會呼叫sub_F38這個function
![](https://i.imgur.com/6vmMZJl.jpg)
sub_F38的assembly有點多，所以直接用Disassembler還原code
首先可以看到他會算兩個值v2跟v3，如果不對的話就會印你數獨很爛，代表這兩個值是拿來檢查數獨的
由此可見byte_202020裡面就會是你數獨放的值，用gdb把值撈出來檢查確認跟輸入一樣(腳本後面再放）
通過v2跟v3的判斷後會把判斷的兩個array印出來並呼叫scanf，就是要求你輸入action code的部份
輸入action code之後程式會用你數獨的array跟你輸入的action code array去跟一個叫byte_202E00的array做XOR運算，並累加v6的值
最後如果v6對的話就會印出byte_202E00的array，反之會印出嘲諷訊息
從這邊可以推斷你的action code輸對才可以算出正確的v6值，且跟Going Crazy那題一樣，輸入正確的action code印出來的array就會是flag
```c=
for ( i = 0; i <= 3160; ++i )
{
    byte_2020E0[i] ^= byte_202020[i % 81];
    v2 += byte_2020E0[i];
}
for ( j = 0; j <= 168; ++j )
{
    aDnkjEnljwLnJhb[j] ^= byte_202020[j % 81];
    v3 += aDnkjEnljwLnJhb[j];
}
if ( v2 == -194062 && v3 == 14763 )
  {
    v6 = 0;
    printf("%3161s%159s", byte_2020E0, aDnkjEnljwLnJhb);
    __isoc99_scanf("%39s", s);
    for ( k = 0; k <= 6014; ++k )
    {
      v0 = byte_202E00[k];
      v1 = byte_202020[k % 81];
      byte_202E00[k] = v1 ^ s[k % strlen(s)] ^ v0;
      v6 += byte_202E00[k];
    }
    if ( v6 == 257498 )
      puts(byte_202E00);
    else
      puts(
        "\n"
        "\n"
        "You are not the agent.....\n"
        "Are you trying to steal our secret?\n"
        "A well-trained killer is coming to your place for a cup of tea...");
    exit(0);
  }
  printf("\n\nWrong, you are bad at sudoku.");
  exit(0);
```
該有的資訊都有了，開始研究解法
首先直接暴搜肯定是不可能的，2^8的40次方(action code的array宣告時大小為40)實在太大
接下來思考有沒有減少暴搜的範圍的方法，不過因為運算是xor的關係，s[i]跟XOR算出來的結果沒有線性關係，沒法使用二分搜
就算可以使用，v6是全部的總和，無法確認個別的s[i]相關的結果總和是多少
強行修改數獨結果去讓xor有消除效果也不太對，因為結果即為flag，數獨結果是預計好的，修改完flag會錯
那根據慣例，沒想法就去看提示，題目中有說flag是ascii art，就是用ascii畫的圖
看完還是沒想法，但是後來突然想到通過數獨判斷的時候他會印兩張圖，那也是ascii art，應該會有ascii art的某些特性
於是我就用gdb dump memory把byte_2020E0給dump下來

在講dump下來的東西之前先講一下我怎麼用gdb debug這個程式的
首先我發現在IDA看到的memory address有點太小，跟往常一樣下breakpoint會下不了
用checksec檢查會發現PIE是開著的，所以每次程式在virtual memory address的位置都會不一樣，很難下breakpoint
後來上網查發現gdb預設是沒有ASLR的，每次跑起來的位置都一樣，但是得先知道它會跑在哪才能下breakpoint，問題變成要找entry point
爬文發現gdb的插件gef有個entry-break的指令，可以幫你先下個斷點在第一個instruction
進入instruction後瘋狂ni+si終於成功找到sub_F38的base address，這樣把IDA上面看到的address加base address就是正確的address，可以直接下斷點

回到dump的部份，下斷點在下面這個指令的後一個指令，就是通過數獨判斷後，程式要印出byte_2020E0把它的base address放進register之後，就可以用gdb.parse_and_eval把rsi裡面的address讀出來
然後再用gdb dump memory filename address address+array長度
byte_2020E0就會被dump到檔名為filename的檔案
```
In sub_F38
0x10A6 lea rsi, byte_2020E0
```
打開檔案裡面的ascii art是TOP SECRET，觀察一下察覺到其實裡面用到的ascii字元沒很多，心血來潮做了個統計
上面是有用到的char，下面是每個char對應的數量
扣掉unicode字元可以發現空白(32)非常多，想想也蠻合理的，總不可能每個地方都塞其他字元，看起來會很亂
由此可以推論ascii art裡面會塞許多空白
```
字元：[10, 32, 9604, 9616, 9617, 9612, 9600, 9608]
數量：[12, 621, 182, 86, 287, 74, 174, 33]
```
有了ascii art會有很多空白這線索後，再回來看算結果的for loop
現在我們知道byte_202E00[k]會有很多是32，也就可以寫成下面註解1的形式
那根據xor的特性可以反過來寫成註解2的形式
這時候如果把32當作action code的輸入的話，因為空白通常不會只有一個，是連續的，這樣結果的array不就會充滿key的片段了ㄇ，太神啦
```c=
for ( k = 0; k <= 6014; ++k )
{
  v0 = byte_202E00[k];
  v1 = byte_202020[k % 81];
  byte_202E00[k] = v1 ^ s[k % strlen(s)] ^ v0;
  //comment 1
  //32 = v1 ^ s[k % strlen(s)] ^ v0;
  //comment 2
  //s[k % strlen(2)] = v1 ^ 32 ^ v0;
  v6 += byte_202E00[k];
}
```
補充一下byte_202E00我不知道他在哪初始化的，但是在sub_F38計算結果前它的內容都沒有改變，所以我就直接先跑一次算結果的地方拿到array開頭的address後，再跑一次並在算結果前把它用gdb腳本抓出來(腳本放最後面）

使用撈出的byte_202E00，數獨結果的array跟全部是空白的s做運算，算出結果，再把結果轉byte寫進檔案裡面並開啟做查看
由於結果有點長，我就擷取片段來展示
從結果可以看到果然有許多像key的片段，擷取最長的一段是decrypt_the_document_of_SCP-2521，看起來很不錯，但是長度只有32
```
G6'!Ghc5},;wXSCT*wv)bcrypt_the_document_of_SCP-252decrypt_the_ mcumen
;of_SCP-2521decrypt_the_document_of_SCP-2521decrypt_the_document_of_SCP-2521decrypt_the_document_of_SCP-252decrypt_th
p' w{oe!lGw)_:Ho}q*)gc=6?;;'*+ cumenzGhf_SCPmK-p~ }uypt_the_document_of_SCP-252decrypt_the_document_of_SCP-2521
```
因為空白會連續，很常接在某個key的字元後面的字元通常也是key
利用這個條件成功把key補到40，decrypt_the_document_of_SCP-2521j*,=6?;\x10，結果發現不是正確答案
覺得很奇怪的我開始亂試，試了一陣子無聊把一開始找到的decrypt_the_document_of_SCP-2521丟進去就噴flag了＝＝
仔細回去看s突然發現它是用strlen，所以循環是根據你的輸入長度決定的，而且它scanf的時候就只吃39個，最後一個留著放\0
也就是說我被宣告的長度騙了QQ
因為strlen只吃到\0，你action code多輸個\0也不會有影響

flag如下：
![](https://i.imgur.com/kXc8SD8.png)

### 腳本
#### 印flag腳本
使用python的gdb腳本來幫忙做輸入，先把輸入都寫input這個檔裡，再用run < input來跑
腳本跑法：
```
gdb --nx -x solve.py ./sudoku
```
```python=
import gdb

sudoku_answer = ['8','1','2','7','5','3','6','4','9','9','4','3','6','8','2','1','7','5','6','7','5','4','9','1','2','8','3','1','5','4','2','3','7','8','9','6','3','6','9','8','4','5','7','2','1','2','8','7','1','6','9','5','3','4','5','2','1','9','7','4','3','6','8','4','3','8','5','2','6','9','1','7','7','9','6','3','1','8','4','5','2']

if __name__ == '__main__':
    with open('input', 'w') as f:
        for c in sudoku_answer:
            f.write(f"{c}\n")
            f.write(f"l\n")
        f.write(f"z\n")
        f.write(f"decrypt_the_document_of_SCP-2521\0")
    gdb.execute('run < input',to_string=True)
    gdb.execute('q',to_string=True)
```
#### 挖各種array＋把key全輸空白算的結果跟2020E0寫檔
很長很醜，總之作用就是可以撈出202020,2020E0,202E00，還有最後算出來的v6值
然後會把key全輸空白的結果寫進叫做blank_array的檔，把2020E0寫進叫做array_2020E0的檔
腳本跑法：
```
gdb --nx -x get_array.py ./sudoku > /dev/null
```
```python=
import gdb
import sys
import string

sudoku_answer = ['8', '1', '2', '7', '5', '3', '6', '4', '9', '9', '4', '3', '6', '8', '2', '1', '7', '5', '6', '7', '5', '4', '9', '1', '2', '8', '3', '1', '5', '4', '2', '3', '7', '8', '9', '6', '3', '6', '9',
                 '8', '4', '5', '7', '2', '1', '2', '8', '7', '1', '6', '9', '5', '3', '4', '5', '2', '1', '9', '7', '4', '3', '6', '8', '4', '3', '8', '5', '2', '6', '9', '1', '7', '7', '9', '6', '3', '1', '8', '4', '5', '2']
addr1 = 0x555555554FB0
addr2 = 0x5555555550AD
addr3 = 0x555555555195
addr4 = 0x5555555550F4
addr5 = 0x55555555512D
addr6 = 0x555555555155
addr7 = 0x555555554FD9

gdb.execute('break *{}'.format(addr1))
gdb.execute('break *{}'.format(addr2))
gdb.execute('break *{}'.format(addr3))
gdb.execute('break *{}'.format(addr4))
gdb.execute('break *{}'.format(addr5))
gdb.execute('break *{}'.format(addr6))
gdb.execute('break *{}'.format(addr7))


def read_reg(reg):
    return gdb.parse_and_eval("${}".format(reg))


def read_2020E0():
    char_pointer = gdb.lookup_type('char').pointer()
    rsi = read_reg('rsi')
    address = rsi
    print("2020E0 base address = {}".format(address), file=sys.stderr)
    gdb.execute(
        f"dump memory array_2020E0 {address} {address+3161}", to_string=True)
    value = []
    for i in range(3168):
        stack_address = gdb.Value(address + i)
        stack_address_pointer = stack_address.cast(char_pointer)
        val = int(hex(stack_address_pointer.dereference() & 0xff), 16)
        value.append(val)
    return value


def read_202E00():
    char_pointer = gdb.lookup_type('char').pointer()
    address = 0x555555756e00
    print("202E00 base address = {}".format(address), file=sys.stderr)
    value = []
    for i in range(6015):
        stack_address = gdb.Value(address + i)
        stack_address_pointer = stack_address.cast(char_pointer)
        val = int(hex(stack_address_pointer.dereference() & 0xff), 16)
        value.append(val)
    return value


def read_202020():
    char_pointer = gdb.lookup_type('char').pointer()
    rsi = read_reg('rax')
    address = rsi
    print("202020 base address = {}".format(address), file=sys.stderr)
    value = []
    for i in range(81):
        stack_address = gdb.Value(address + i)
        stack_address_pointer = stack_address.cast(char_pointer)
        val = int(hex(stack_address_pointer.dereference() & 0xff), 16)
        value.append(val)
    return value


def read_compare_value():
    int_pointer = gdb.lookup_type('int').pointer()
    rbp = read_reg('rbp')
    address = rbp-0x58
    print("compare value address = {}".format(address), file=sys.stderr)
    stack_address = gdb.Value(address)
    stack_address_pointer = stack_address.cast(int_pointer)
    val = int(stack_address_pointer.dereference())
    return val


if __name__ == '__main__':
    s = ['0']*40
    with open('input', 'w') as f:
        for c in sudoku_answer:
            f.write(f"{c}\n")
            f.write(f"l\n")
        f.write(f"z\n")
        for c in s:
            f.write(c)
    gdb.execute('run < input', to_string=True)
    
    sudoku = read_202020()
    '''
    for i in sudoku:
        print(i, end=' ', file=sys.stderr)
    print('', file=sys.stderr)
    '''
    gdb.execute('delete 1', to_string=True)
    gdb.execute('c', to_string=True)
    print(f"v0 = {read_reg('eax')}",file=sys.stderr)
    gdb.execute('delete 7', to_string=True)
    gdb.execute('c', to_string=True)
    
    v = read_2020E0()
    
    b_array = b''
    for i in v:
        if i != 0:
            b_array += i.to_bytes(1, 'big')
            #print(i,end=' ',file=sys.stderr)
    print(b_array.decode('utf-8'),file=sys.stderr)
    
    value = read_202E00()
    '''
    b_array = b''
    for i in value:
        if i != 0:
            b_array += i.to_bytes(1, 'big')
            #print(i,end=' ',file=sys.stderr)
    #print(b_array.decode('utf-8'), file=sys.stderr)
    '''
    gdb.execute('delete 2', to_string=True)
    gdb.execute('c', to_string=True)
    value_0 = read_reg('r12d')
    #print('v0 = {}'.format(value_0), file=sys.stderr)
    #print(f"byte_202E00_address = {read_reg('rax')}",file=sys.stderr)
    gdb.execute('delete 4', to_string=True)
    gdb.execute('c', to_string=True)
    value_1 = read_reg('r13d')
    #print('v1 = {}'.format(value_1), file=sys.stderr)
    gdb.execute('delete 5', to_string=True)
    gdb.execute('c', to_string=True)
    value_s = read_reg('eax')
    #print('s = {}'.format(value_s), file=sys.stderr)
    gdb.execute('delete 6', to_string=True)
    gdb.execute('c', to_string=True)
    
    correct_answer = read_compare_value()
    print('compare value = {}'.format(correct_answer),file=sys.stderr)
    #address = 0x555555756e00
    #gdb.execute(f"dump memory array202E00 {address} {address+6015}",to_string=True)
    b_array = b''
    for i in range(6015):
        v0 = value[i]
        v1 = sudoku[i % 81]
        result = v0 ^ 32 ^ v1
        if result != 0:
            b_array += (result).to_bytes(1, 'big')
    with open('blank_array', 'wb') as f:
        f.write(b_array)
    gdb.execute('q',to_string=True)
    

```
#### 統計ascii腳本
最後是統計2020E0裡面有哪些ascii字元跟對應數量的腳本，會先印出可愛的TOP SECRET，最後印出上面writeup解釋過的兩個list
跑法就python3的跑法，要先有array_2020E0這個檔案
```python=
with open('array_2020E0', 'r') as f:
    array = f.read()
    char_list = []
    count = []
    for c in array:
        if ord(c) not in char_list:
            char_list.append(ord(c))
            count.append(0)
        else:
            count[char_list.index(ord(c))] += 1
    print(array)
    print(char_list)
    print(count)
```