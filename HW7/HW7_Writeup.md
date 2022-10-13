###### tags: `程式安全`
# Secure Programming HW7 Writeup
## Going Crazy
### 解法
這題我是用IDA7.5+golanghelper腳本、ghidra9.1.2+gotools擴充套件做靜態分析，用gdb做動態分析
首先用golanghelper還原function name，去看main.main的CFG
從裡面可以得知，在call strings_Split跟main_check_input這兩個看起來很重要的function之前要先經過一些輸入檢查
檢查中比較重要的是開頭跟結尾的byte要是x

由於strings_Split是golang的function，直接去官網看它的說明，它會將一個string，利用delimiter切成一個array的string回傳
實際用gdb檢查strings_Split執行前傳進去的參數可以發現它會從string map去拿英文的逗號，這個就是delimiter

trace完strings_Split後來看main_check_input
可以看到經過golang增加stack的routine跟前處理後會進入一個迴圈裡面，迴圈裡面有strconv_Atoi跟main_bezu這兩個function

想去看這兩個function的參數跟回傳值卻被前面的判斷給擋掉了，會噴out of index
```
0x48E6BD cmp rcx,rdx
```
這代表輸入可能有問題
我一開始並沒有使用逗號來分割string，想說可能跟分割的數量有關，就開始測試輸多少段string可以過，一路測到36個string就過了

strconv_Atoi一樣是內建function，目的是把string轉成對應的integer，看來是想對輸入做數學運算
main_bezu裡面會先call main_rchvf去算一個看起來很像輾轉相除法的東東，main_rchvf回傳回來要是1才不會噴錯，然後main_bezu回傳的值如果是負的會加一個定值加到正為止
從這三個條件推斷這個數學運算很有可能是算模反元素的擴充歐幾里德

main_bezu算出來的值會被拿去跟rcx做比較，如果不一樣就會彈出迴圈並噴錯，所以Atoi轉成的數字要正確才不會被彈掉

接著開始研究要改哪個數字才有用，發現第一次要改第16個，先試著從0開始爆搜到main_bezu算出來的結果跟rcx一樣為止，改到114成功通過判斷

為了觀察它會用到哪個位置的數字做運算，先在gdb下個breakpoint，下在進去main_bezu的前一行，然後利用有順序的輸入像是x0,1,2,...,35x，就可以從rax判斷是哪個值被丟進去計算，結果發現算的位置應該是事先算好的且不規則

另外從要不斷改變輸入，與它不會印出其他像flag的東西來推斷，我們的輸入即為flag
也就是只要不斷爆搜就可以得到最終的flag，可以使用python來撰寫gdb的腳本，就可以自動地完成這件事情

不過後來想說有沒有更聰明的寫法，發現rcx的值應該是事先就在0x48E64B那邊算好的，如果事先知道值就可以先反過來算模反元素知道我們要輸進去的值是多少
觀察rcx跟rdx比較之前rcx最後一次被賦值是
```
mov rcx, [rsp+rax*8+278h+var_128]
```
這個值會跟隨象徵迴圈次數的rax進行變化，所以我們第一次跑過來就可以透過增加rax先把所有之後的rcx都偷偷存起來，就可以一次算好所有flag的值

但是還需要知道是哪個byte被拿去做運算
位置同樣應該是事先就在0x48E64B那邊算好的，找了一下發現第一次跑迴圈判斷的rcx就是第16個(0xf)，而且rcx的值一樣是會跟隨rax做變化，可以先透過增加rax來拿到
```
0x48E6B0 mov rcx, [rsp+rax*8+278h+var_248]
0x48E6BD cmp rcx,rdx
```
都想好就可以開始寫腳本了，腳本流程如下：
(1)先跑一次到第一個迴圈的0x48e6b0拿到算的位置順序跟正確答案(read_box function)
(2)建好flag要用的list，長度為36
(3)利用正確答案算模反元素，反過來先算出正確的byte，並利用位置順序存在正確的位置
(4)最後得到flag並印出

腳本跑法：
```
gdb --nx -x solve_mod.py ./gogo
```

以下為腳本內容：
```python=
import sys
import gdb
import string
import time

n = 0xFBC56A93

def xgcd(a, b):
    """
    Extented Euclid GCD algorithm.
    Return (x, y, g) : a * x + b * y = gcd(a, b) = g.
    """
    if a == 0: return 0, 1, b
    if b == 0: return 1, 0, a

    px, ppx = 0, 1
    py, ppy = 1, 0

    while b:
        q = a // b
        a, b = b, a % b
        x = ppx - q * px
        y = ppy - q * py
        ppx, px = px, x
        ppy, py = py, y

    return ppx, ppy, a

def invmod(e, n):
    x, y, g = xgcd(e, n)
    return x % n

def read_reg(reg):
    return gdb.parse_and_eval("${}".format(reg))

break_addr = 0x000000000048e6b0
gdb.execute('break *{}'.format(break_addr))

def read_box():
    int_pointer = gdb.lookup_type('int').pointer()
    rsp, rax = read_reg('rsp'), read_reg('rax')
    address = rsp + rax*8 + 0x30
    pbox = []
    for i in range(36):
        stack_address = gdb.Value(address + i*8)
        stack_address_pointer = stack_address.cast(int_pointer)
        val = int(stack_address_pointer.dereference())
        pbox.append(val)
    
    address = rsp + rax*8 + 0x150
    value = []
    for i in range(36):
        stack_address = gdb.Value(address + i*8)
        stack_address_pointer = stack_address.cast(int_pointer)
        val = int(stack_address_pointer.dereference())
        
        value.append(int(hex(val & 0xffffffff),16))
    return pbox, value



if __name__ == '__main__':
    initial = [str(i) for i in range(128, 128+36)]
    with open('input','w') as f :
            f.write(f'x{",".join(initial)}x')
    gdb.execute('run < input', to_string=True)
    pbox, value = read_box()
    flag = [None] * 36
    for idx, loc in enumerate(pbox) :
        flag[loc] = chr(invmod(value[idx],n))
    print(''.join(flag))
    gdb.execute('q',to_string=True)
```