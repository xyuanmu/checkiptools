checkiptools
============

集成 checkgoogleip，python(带netaddr)，以及一些实用的小工具。
源代码取自 [checkgoogleip](https://github.com/moonshawdo/checkgoogleip)、[XX-Net](https://github.com/XX-net/XX-Net)、双手码出，感谢大家的辛勤付出！


目录文件说明：
 * bindip.bat             合并ip段批处理，生成 ip_bind.txt ，里面IP均用 | 分割供GoAgent使用
 * bindip.py              代码文件，Linux 命令 $ python bindip.py
 * bindip_json.bat        合并ip段批处理，生成 ip_json.txt ，里面IP为json格式供GoProxy使用
 * bindip_json.py         代码文件，Linux 命令 $ python bindip_json.py
 * checkip.bat            扫描IP工具
 * checkip.py             代码文件，Linux 命令 $ python checkip.py，修改说明参考：[README2.md](https://github.com/xyuanmu/checkiptools/blob/master/README2.md)
 * generate_googleip.bat  用于整合IP段，将IP段复制到 ip_original_list.txt 中，运行批处理即可生成 googleip.txt 和 googleip.ip.txt
 * generate_googleip.py   代码文件，Linux 命令 $ python generate_googleip.py
 * googleip.ip.txt        已转换成CIDR格式的IP段，可用于 XX-Net 或者 GoGo Tester
 * googleip.txt           已转换成 xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx 格式的IP段，可用于 XX-Net
 * ip_original_list.txt   包含原始IP段的文件，支持 checkgoogleip IP组格式，可用 generate_googleip 整合IP段，**以后只需将新IP段添加进来用 generate_googleip.bat 转换即可**
 * enjoy it!
