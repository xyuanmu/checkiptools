CheckIpTools
============

集成 checkgoogleip，python(带netaddr)，以及一些实用的小工具。源代码取自 [checkgoogleip](https://github.com/moonshawdo/checkgoogleip)、[XX-Net](https://github.com/XX-net/XX-Net)、双手码出，感谢大家的辛勤付出！

在 [checkgoogleip](https://github.com/moonshawdo/checkgoogleip) 原有基础上增加逐个扫描googleip-001.txt、googleip-002.txt...以控制内存，并将扫描结果保存到tmp文件夹，扫描完成后自动删除googleip文件。若无googleip-001.txt命名规则的文件则扫描 googleip.txt。

## 下载地址
* Windows：[CheckIpTools](https://github.com/xyuanmu/checkiptools/archive/master.zip)
* Linux：[CheckIpTools For Linux](https://github.com/xyuanmu/checkiptools/archive/Linux.zip)
* 因新版包含中文字符：[若乱码请下载1.0版](https://codeload.github.com/xyuanmu/checkiptools/zip/1.0)


## 目录文件说明：
 * !iptools.bat         转换IP小工具，输入相应编号进行操作
 * checkip.bat          用于扫描谷歌IP工具的工具，提取自[checkgoogleip](https://github.com/moonshawdo/checkgoogleip)，使用说明参考：[README2.md](https://github.com/xyuanmu/checkiptools/blob/master/README2.md)
 * googleip.txt         已转换成CIDR格式的IP段，可用于 [XX-Net](https://github.com/XX-net/XX-Net) 或者 GoGo Tester（记得改名.ip结尾）
 * ip_range_bad.txt     包含IP段黑名单的文件，支持 checkgoogleip IP组格式，支持 # 注释
 * ip_range_origin.txt  包含原始IP段的文件，支持 checkgoogleip IP组格式，支持 # 注释，**以后只需将新IP段添加进来用 !iptools.bat 转换即可**
 * enjoy it!

## 工具预览：
![checkiptools](https://cloud.githubusercontent.com/assets/12442896/10902255/0abb9258-8236-11e5-8ba1-191cc36b804e.png)

## 20151103更新
* IP段统一使用CIDR格式
* 修复BUG：No such file or directory: ''
* 增加整合tmp目录下的可用IP到 ip_all.txt

## 20151023更新
* 更新IP分段命名规则为001、002
* 支持扫描10个以上IP分段文件

## 20151022更新
* 新增IP数量超过1KW时自动分割，生成 googleip-i.txt 命名的IP段文件
* 优先扫描 googleip-i.txt 文件IP段，逐个扫描并将结果存到tmp文件夹，若无则扫描 googleip.txt

## 20151018更新
* 优化代码
* 增加Linux系统版本，到这里下载：[CheckIpTools For Linux](https://github.com/xyuanmu/checkiptools/tree/Linux)

## 20151016更新
* 增加工具选项，更直观
* 增加导出 ip_tmpok.txt 为XX-Net格式，便于复制到 data/gae_proxy/good_ip.txt
* 增加IP格式互转 GoAgent <==> GoProxy
* **新版本包含中文字符，出现乱码[请下载1.0版](https://codeload.github.com/xyuanmu/checkiptools/zip/1.0)，[使用说明](https://github.com/xyuanmu/checkiptools/blob/1.0/README.md)。**
