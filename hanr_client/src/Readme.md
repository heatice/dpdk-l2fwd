### Usage
1. 仅接收数据包，打印统计信息
```shell
$ sudo ./hanr_client
```
2. 仅接收数据包，打印统计信息和数据包详情
```shell
$ sudo ./hanr_client -- -v
```
3. 收发数据包，打印统计信息
```shell
$ sudo ./hanr_client -- -t [1|2|3]
1：注册数据包 
2：注销数据包 
3：查询数据包 
```


4. 收发数据包，打印统计信息和数据包详情
```shell
$ sudo ./hanr_client -- -t [1|2|3] -v
```
