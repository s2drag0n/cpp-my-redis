# SERVER-ANALYSIS

## main

程序入口

初始化循环链表的节点，将节点的next和pre都指向自己。操作对象是g_data中的idle_list。

建立socketfd，设置可重用，绑定ip和port，开始监听。
设置为非阻塞

申请kevent结构体，加入监听fd，申请kqueuefd，开始循环。

### 循环内容

将g_data中的Conn Map（从fd映射到Conn结构体）中的所有连接的fd加入kqueue事件循环。其中如果当前连接状态为REQ也就是读取请求阶段，就将其设置为侦听可读事件，否则将其设置为可写事件。

调用next_timer_ms获得下一个定时器。获得定时器的方式是：

1. 首先检查idele_next头节点的下一个节点，通过这个节点找到节点对应的Conn结构体，然后访问Conn的idle_start值，将其加上超时时间*1000，作为定时器值。（idle timers 闲置定时器，如果我们将每个连接的超时时间定义为其上次接受处理时间+规定的超时时间，那么链表的头节点的下一个节点存放的是最早会超时的连接的上次访问时间。）
2. 然后检查g_data中heap（一个由vector实现的最小堆结构）中的堆顶中存储的定时器值。（ttl timers 生存时间定时器）
3. 将两者中更早的一个作为定时器返回

将此定时器设置为kevent时间循环的超时时间.

开始处理接收到的活跃的Conn：

1. 如果是监听fd，就使用[accept_new_conn](#1)接受新的连接请求。
2. 如果是连接的可读/写事件，则调用[connection_io](#2)去处理相应事件。如果在处理后，Conn的状态变成了end，则使用[conn_done][]来删除相应的Conn。

## <span id="1">accept_new_conn</span>

使用accept获取到connfd，并设置其为非阻塞。

新建一个Conn指针，并malloc相应内存。设置此Conn的fd、state（初始为REQ）、rbuf_size、wbuf_sent、wbuf_size、idele_start为获取当前时间。

将此Conn的闲置定时器列表节点idle_list插入g_data中保存的闲置定时器链表节点的前面一个位置。

将Conn放入Conn Map。

## <span id="2">connection_io</span>

首先将该conn的idele_start设置为当前的时间。然后从循环链表中删除掉此conn对应的定时器节点，然后将此定时器节点插入到链表头部，也就是将即将要处理的conn的idle_list节点放到闲置定时器链表头部。

开始处理：如果REQ，则使用[state_req](#3)；反之使用[state_res](#state_res)。

### <span id="3">state_req</span>

整个函数就是一个循环，只要try_fill_buffer返回结果为真，就一直循环执行try_fill_buffer。函数try_fill_buffer如下：

一直对fd进行循环读取，直到rbuffer被读满。如果出现EAAGAIN或者EWOULDBLOCK，代表着即将阻塞，直接返回false，同时state_req结束，代表这一次处理完毕。如果出现其他错误或者客户端断开连接（EOF），则直接将此conn设置为END状态，并退出处理程序，随后在主函数中会将这个conn删除。

如果正常执行，则对函数[try_one_request](#4)进行循环，如果其返回值为正，则继续循环。然后此函数的返回值为state是否仍==REQ。

### <span id="4">try_one_request</span>

这个函数主要负责任务是进行一次request的读取。

如果rbuf_size小于4，则说明还没有接收到足够的字节数，因为规定的消息格式是每一个请求都有一个4字节的前缀，代表这一次请求的字节数。如果够4字节，则将这4个字节读入变量len。

如果4+len比rbuf_size大，则说明rbuffer还没接收到一整条完整的消息。这种情况和上面的情况一样都应该直接返回false，状态仍为req，待由下一轮继续读取数据。

如果4+len大于规定的最大消息字节数，则将状态设置为end，并返回false。

定义一个string的vector，叫做cmd，用来存放解析出来的请求。调用[parse_req](#5)函数进行命令解析，并将解析出来的请求放到cmd中。

如果返回-1，则说明请求有问题，设置conn状态为end，并返回false。

如果正确，则调用[do_request](#do_request)来处理这一次请求，并且得到待输出结果out（一个字符串）。

如果4+out的size比规定的最长消息长度要大，则将out清除，然后返回一个err到out中。否则，将out长度冷放到wbuf的前4字节，然后放入out本身。

将rbuffer中的未读字段放到开头。设置conn的状态为RES，调用[state_res](#state_res)函数进行数据的发送。

返回conn的状态==REQ，如果是则代表还要继续进行此函数。

### <span id="5">parse_req</span>

请求的前4个字节中存放的是这一条请求包含几个字符串，然后后面的跟着的字节分别是每个字符串的长度和字符串本身，如下表所示。

| Column1    | Column2    | Column3    | Column4    | Column5    | Column6 |
|---------------- | --------------- | --------------- | --------------- | --------------- | --------------- |
| 字符串个数n    | msg1len    | msg1    | msg2len    | msg2   | ...   |

循环读取n个字符串并放入cmd。如果在这个过程中出现了len<4、len不足容纳这么多条命令，n>规定的请求最大字符串个数、len没有正好容纳字符串的情况，代表这是一条错误的请求，直接返回-1。

正确解析则返回0。

### <span id="state_res">state_res</span>

循环执行try_flush_buffer，其内容为：

循环发送wbuffer，直到其中数据被发送完毕。错误情况基本等同try_fill_buffer，要阻塞时直接返回false，下次再写。错误则直接设置为end，然后返回false。

如果发送完毕，则返回false完成发送，否则返回true，继续发送。

### <span id="do_request">do_request</span>

一共有8种命令，分别是keys、get、set、del、zadd、zrem、zscore、zquery，它们有各自的处理函数来生成对应的回复out。// TODO

##### do_keys

调用out_arr函数，将out的Array标识和存储的

##### do_get

用于查询key对应的value。是选新建一个Entry，将其的key设置为待查询的key，将其hcode设置为待查询的hcode（hcode仅仅和key有关）。

调用hm_lookup去哈希表g_data中的db中去查询上面新建的Entry。//TODO

- 如果没找到，返回nil
- 如果查询到的node对应的Entry中的类型不是STR，则返回一个错误，错误信息为expect string type
- 否则返回这个string。

##### do_set

同样新建一个同key和hcode的Entry。查询这个Entry，如果找到了先判断类型是否为STR，然后将其value设置为给定的value。

如果还不存在，则new一个Entry，设置对应的key、hcode、val，调用hm_insert将其插入到g_data的db中去。//TODO

##### do_del

同样新建Entry，调用hm_pop将其从db中删除。如果删除时返回非空，也就是删除成功，则调用entry_del将此Entry删除。//TODO

##### do_zadd

##### do_zrem

##### do_zscore

##### do_zquery

