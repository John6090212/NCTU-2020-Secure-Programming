# NCTU-2020-Secure-Programming
台大、交大與台科大共同開設的程式安全課程，課程內容為學習資安與CTF競賽常用的技術。
* HW0: CTF簡易測驗
* HW1-3: CTF中的密碼學相關題目
    * HW1: 練習Padding Oracle attack與LFSR
    * HW2: 練習RSA相關漏洞
    * HW3: 練習智能合約的相關漏洞
* HW4-6: CTF中的Web相關題目
    * HW4: 練習從.git檔偷取資料、用XSS雙層fetch偷取資料以及用Lax+POST完成CSRF攻擊
    * HW5: 練習繞過PHP的WAF與SQL Injection+quine
    * HW6: 練習從php的class機制觸發Phar反序列化漏洞與利用SSRF達成Redis RCE
* HW7-8、HWC: CTF中的Reverse(逆向工程)相關題目
    * HW7: 練習逆向golang題目並撰寫python gdb腳本
    * HW8: 熟悉逆向流程與看懂隱藏在題目的巧思，包含避開ptrace攔截、利用Ascii art與XOR特性等等
    * HWC: 練習內容為gzip與base64的逆向題目
* HWA-B: CTF中的Pwn相關題目
    * HWA: 結合簡易逆向、buffer overflow、偷取canary及PIE+libc base、串ROP chain等多種Pwn的技巧
    * HWB: 練習heap exploitation技巧