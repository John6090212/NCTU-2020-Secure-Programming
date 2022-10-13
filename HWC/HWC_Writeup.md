###### tags: `程式安全`
# Secure Programming HWC Writeup
## ChristmasGift
### 解法
先file一下確認是linux執行檔
接著用IDA decompile看一下main function
首先會strcpy一串很醜的東東，然後scanf要求你輸入256長度的字串
如果輸入跟那串很醜的東東一樣就會做某種運算，然後把東西印出來
不一樣就印wrong
```c=
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v3; // r12
  int i; // [rsp+Ch] [rbp-234h]
  char s2[272]; // [rsp+10h] [rbp-230h] BYREF
  char s1[264]; // [rsp+120h] [rbp-120h] BYREF
  unsigned __int64 v8; // [rsp+228h] [rbp-18h]

  v8 = __readfsqword(0x28u);
  strcpy(
    s2,
    "JZC33MJPDC48UXXJ94BBQOR0JJR4AO0W02PHZ4VZRJAEXL3OUI02FQ4GSQIDGBFT70VESKNAAUEJW4RR9EQOCJ9PKT7W9FBMJDVK6X9MT7K1HY30MSA4"
    "H3Y9FTV0O7Z6FQ5I1J8R6KSCMWKFSDGCMWARIJTLPLRO8KUYQW2F46ZV6YWIVFNCZDQRCTAM5JVGQMEU2LFPS5DUDOY4130XB50V91PWHCIO0AD1RHTR"
    "673DPX36TA2UWA48FD34Y2W6");
  __isoc99_scanf("%256s", s1);
  if ( !strcmp(s1, s2) )
  {
    for ( i = 0; i <= (int)&unk_3347DA; ++i )
    {
      v3 = byte_201020[i];
      byte_201020[i] = s2[i % strlen(s2)] ^ v3;
    }
    puts("Ok, that sounds good");
    write(1, byte_201020, (size_t)&unk_3347DB);
  }
  else
  {
    puts("wrong");
  }
  return 0LL;
}
```
那就先輸入一樣的字串看看，結果噴了一長串更醜的東東，很像是binary
於是把他導到一個檔案，用file看看是什麼類型的binary，發現是gzip的壓縮檔
![](https://i.imgur.com/oVzrgif.png)
gunzip解壓縮後發現內容又是一個linux執行檔，IDA decompile一看又是長差不多的東西，只有很醜的那串字不一樣，看起來這是個解壓縮遊戲
由於那串字在binary的offset都一樣，可以靠dd去切出來，就可以寫腳本瘋狂解壓縮了

解壓縮用無限迴圈停不下來，代表解到某個index之後那串字的offset可能就怪怪的，導致解得東西歪掉了
逐漸縮小範圍發現到999次後gzip有噴錯，於是999次後把binary打開檢查
發現原來是string的長度變短了，變成
```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@terrynini@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
```
手動輸進去後就噴flag了

下面是我解題用的腳本，內容大致如下
1.用dd切出key(那串string)
2.把上次迴圈解壓縮出來的gift執行檔的權限改成可以執行
3.執行gift，用input redirection輸key，用output redirection導到gift.gz的壓縮檔
4.用gunzip解壓縮
重複999次，最後一次事先把key寫好就可以直接噴flag
```python=
#!/usr/bin/python3
import os

t = 0
for i in range(1000):
    if i != 999:
        print(f"unzip {t} times")
        os.system("dd if=gift of=key ibs=1 skip=2576 count=256")
        os.system("cat key")
        os.system("chmod +x gift")
        os.system("./gift < key > gift.gz")
        os.system("gunzip -d -f gift.gz")
    else:
        os.system("echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@terrynini@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ > final_key")
        os.system("chmod +x gift")
        os.system("./gift < final_key")
    t += 1
```
## JustOnLinux
### 解法
有附flag檔，看起來像加密或encode之後的結果，先去看執行檔file確認是linux執行檔
接著用IDA decompile看一下，找不到main function
所以先執行看看有沒有什麼字串可以幫忙找，出現了usage: babyencode string
用IDA的search text可以在rodata區域找到，再用Xrefs graph to就可以知道它會在sub_400B6D裡面用到

然後就可以看sub_400B6D在幹嘛，用Xrefs graph to發現call它的是_start，應該就是main function沒錯
首先它會確定argc>1，然後把程式的第二個參數的address丟進strlen裡面
由此可見第二個參數要輸一個string
算完input length後會*4/3當作result length並malloc一個result length+1的array
```c=
string_address_v20 = *(_QWORD *)(a2 + 8);
    string_length_v15 = j_strlen_ifunc(string_address_v20);
    result_length_v16 = 4 * ((string_length_v15 + 2) / 3);
    v21 = malloc_41F810(result_length_v16 + 1);
```
確認malloc成功後開始對input string進行轉換，接下來會拿出input string的三個char，然後合成一個int存在v19裡面
然後把v19的每三個byte的24bit切成4個6bit當作array index，去找出aVwxyzabcdefghi的值存進result裡面
&63的動作會讓查詢不會超界，array長度是64
接著會看情況補空白，並將result用printf印出
```c=
if ( v21 )
    {
      v12 = 0;
      v13 = 0;
      while ( v12 < string_length_v15 )
      {
        v5 = v12++;
        v17 = *(char *)(v5 + string_address_v20);
        if ( v12 >= string_length_v15 )
        {
          v7 = 0;
        }
        else
        {
          v6 = v12++;
          v7 = *(char *)(v6 + string_address_v20);
        }
        v18 = v7;
        if ( v12 >= string_length_v15 )
        {
          v9 = 0;
        }
        else
        {
          v8 = v12++;
          v9 = *(char *)(v8 + string_address_v20);
        }
        v19 = (v18 << 8) + (v17 << 16) + v9;
        *((_BYTE *)v21 + v13) = aVwxyzabcdefghi[(v19 >> 18) & 0x3F];
        *((_BYTE *)v21 + v13 + 1) = aVwxyzabcdefghi[(v19 >> 12) & 0x3F];
        *((_BYTE *)v21 + v13 + 2) = aVwxyzabcdefghi[(v19 >> 6) & 0x3F];
        v10 = v13 + 3;
        v13 += 4;
        *((_BYTE *)v21 + v10) = aVwxyzabcdefghi[v19 & 0x3F];
      }
      v11 = string_length_v15;
      if ( string_length_v15 % 3 )
      {
        for ( i = 0; ; ++i )
        {
          v11 = string_length_v15 % 3;
          if ( i >= 3 - string_length_v15 % 3 )
            break;
          *((_BYTE *)v21 + result_length_v16 + string_length_v15 % 3 + i - 3) = 32;
        }
      }
      *((_BYTE *)v21 + result_length_v16) = 0;
      printf((unsigned int)"%s", (_DWORD)v21, result_length_v16, v11, v3, v4, a2);
      sub_4200D0(v21);
      result = 0LL;
    }
```
來整理一下現在有的線索:
1.根據usage提示這是某種string encoding
2.result string會是input string的4/3長度
3.每次會拿input string的3個byte轉成4個char放進result string

這東西越看越眼熟阿，不就是base64 encode嗎XD
於是開心的把flag拿去decode，結果解出了一堆框框＝＝
只好開始重新檢查一次，檢查很久後想說來看看那個轉換用的array，然後就驚呆了
這長得跟我記得的不一樣阿...
```
vwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~o
```
原來base64 encode的表被偷換掉了，那就轉回原本的表就好，因為6 bit對應的位置是一樣的，easy
轉回正確的encode之後用base64 decode就拿到flag了
感謝逆逆的大恩大德，放寒假~

```python=
import base64

normal_base64_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
strange_base64_table = 'vwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~o'

encode_flag = '' 
with open('flag','r') as f:
    s = f.read()
    for c in s:
        index = strange_base64_table.find(c)
        encode_flag += normal_base64_table[index]
    flag = base64.b64decode(encode_flag).decode('utf-8')
    print(flag)
```





