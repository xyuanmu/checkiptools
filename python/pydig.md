pydig
=====

## 软件说明
* 一个简单的使用dig扩展功能获取谷歌IP的工具
* 支持平台：Windows | Linux
* 支持网站：[Best DNS](http://www.bestdns.org/), [Ungefiltert surfen](http://www.ungefiltert-surfen.de/)

## 使用方法：
**启动程序命令：**Windows 直接双击 dig.bat，Linux 使用命令 `$ python pydig.py`    

1. 方法一：
  1. 在 dig.bat 所在目录新建一个 dig_url.txt。
  2. 到 [Best DNS](http://www.bestdns.org/) 首页 **Where do you need a DNS from?** 下方选一个地区的网址进行复制，或者到 [Ungefiltert surfen](http://www.ungefiltert-surfen.de/) 选择 **Öffentliche Nameserver nach Ländern** 下方的地区网址进行复制，粘贴到 dig_url.txt，一行一条。
  2. 启动程序获取返回的IP段。
2. 方法二：
  1. 在 dig.bat 所在目录新建一个 dig_ip.txt，将模拟IP地址复制进去，一行一个。
  2. 启动程序获取返回的IP段。
3. 方法三：
  1. 启动程序，输入网址或IP地址，按下回车自动 dig 网址中的IP。

* 生成 dig_range.txt 后将里面的IP段导入 googleip.txt 中并使用 checkip 扫描。
* 其他功能修改请参考 pydig.py 文件里的中文注释。
