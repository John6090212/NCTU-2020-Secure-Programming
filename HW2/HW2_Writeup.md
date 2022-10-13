###### tags: `程式安全`
# Secure Programming HW2 Writeup
## RSA
### 解法
題目中給的資訊如下:
```python=
p = getPrime(512)
q1 = next_prime(2 * p)
q2 = next_prime(3 * q1)

n = p * q1 * q2
e = 65537
```
一開始原本想直接爆root，但發現e也沒很小，ciphertext可能被mod過了
於是轉換思路開始決定強行分解n
但是next_prime的操作讓p跟q1,q2其實沒有很直接的關係，就算有也是一元三次方程式很難解
後來突然想到有p的話，q1跟q2都可以從next_prime拿到，相乘起來等於n就可以知道是對的p
所以解法改為爆搜p

因為太大的p乘起來的結果會超過n，反之會小於n，我們可以用二分搜的方式去找，讓搜尋的時間變成log(n)
搜到正確的p之後就可以一併拿到q1跟q2
然後算出totient，就可以拿到e的inverse d
最後用c^d mod n得到明文，就拿到flag了

下面是我解題的程式:
```python=
import gmpy2
from Crypto.Util.number import *

n = 22001778874542774315484392481115711539281104740723517828461360611903057304469869336789715900703500619163822273767393143914615001907123143200486464636351989898613180095341102875678204218769723325121832871221496816486100959384589443689594053640486953989205859492780929786509801664036223045197702752965199575588498118481259145703054094713019549136875163271600746675338534685099132138833920166786918380439074398183268612427028138632848870032333985485970488955991639327
c = 1067382668222320523824132555613324239857438151855225316282176402453660987952614935478188752664288189856467574123997124118639803436040589761488611318906877644244524931837804614243835412551576647161461088877884786181205274671088951504353502973964810690277238868854693198170257109413583371510824777614377906808757366142801309478368968340750993831416162099183649651151826983793949933939474873893278527484810417812120138131555544749220438456366110721231219155629863865
e = 65537
def binary_search(low,high,num):
    print("low is:{}".format(low))
    print("high is:{}".format(high))
    if high >= low:
        mid = (high+low) // 2
        p = mid
        q1 = gmpy2.next_prime(2*p)
        q2 = gmpy2.next_prime(3*q1)
        result = p * q1 * q2
        if result == num:
            return p;
        elif result > num:
            return binary_search(low,mid-1,num)
        else:
            return binary_search(mid+1,high,num)
    else:
        return -1


p = binary_search(0,2**512,n)
q1 = gmpy2.next_prime(2*p)
q2 = gmpy2.next_prime(3*q1)
print("p is: {}".format(p))
print("q1 is: {}".format(q1))
print("q2 is: {}".format(q2))

#p = 12239363968862301655032671889408678336365197765290722249588768227649140689948872816725306416825242592654590826028443535297344717808724316145004300860420999
#q1 = 24478727937724603310065343778817356672730395530581444499177536455298281379897745633450612833650485185309181652056887070594689435617448632290008601720842217
#q2 = 73436183813173809930196031336452070018191186591744333497532609365894844139693236900351838500951455555927544956170661211784068306852345896870025805162527169 

phi = (p-1)*(q1-1)*(q2-1)
d = inverse(e,phi)
print(long_to_bytes(pow(c,d,n)))
```

flag如下:
>FLAG{Ew9xeANumjDr6bXemHsh}

## LSB
### 解法:
主要使用講義中LSB的解法二來解題
程式的部分是利用講師大大在github上面的code做修改
https://github.com/oalieno/Crypto-Course/blob/master/RSA/LSB-Oracle/solve2.py
因為是mod 3的關係，參數需要做些微調整
但解題觀念不變，可以想成在base3下面操作，每次把m除以3就可以得到一個bit，總共做ceil(log(2^1024))次，log的base為3
有想說可不可以用講義中LSB的解法一來解，但是mod 3的餘數好像沒法推區間，解法二比較好推廣的樣子

下面是我改完的程式:
```python=
from pwn import *
from Crypto.Util.number import *
import math
conn = remote('140.112.31.97', 30001)

n = int(conn.recvline().split(b' = ')[1])
c = int(conn.recvline().split(b' = ')[1])
e = 65537

inv  = inverse(3, n)
inve = pow(inv, e, n)

flag, x = 0, 0
for i in range(math.ceil(math.log(2**1024,3))):
    #print(i)
    conn.sendline(str(c))
    m = int(conn.recvline().split(b' = ')[1])
    bit = (m - x) % 3
    x = inv * (x + bit) % n
    flag += bit * 3**i
    c = (c * inve) % n

print(long_to_bytes(flag))

```
flag如下:
>FLAG{nF9Px2LtlNh5fJiq3QtG}

