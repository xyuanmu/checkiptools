CheckIpTools
============

集成 checkgoogleip，python(带netaddr)，以及一些实用的小工具。源代码取自 [checkgoogleip](https://github.com/moonshawdo/checkgoogleip)、[XX-Net](https://github.com/XX-net/XX-Net)、双手码出，感谢大家的辛勤付出！

在 [checkgoogleip](https://github.com/moonshawdo/checkgoogleip) 原有基础上增加逐个扫描googleip-001.txt、googleip-002.txt...以控制内存，并将扫描结果保存到tmp文件夹，扫描完成后自动删除googleip文件。若无googleip-001.txt命名规则的文件则扫描 googleip.txt。

## 下载地址
* Windows：[CheckIpTools](https://github.com/xyuanmu/checkiptools/archive/master.zip)
* Linux：[CheckIpTools For Linux](https://github.com/xyuanmu/checkiptools/archive/Linux.zip)


## 目录文件说明：
 * !ptools.bat          转换IP小工具，输入相应编号进行操作
 * checkip.bat          用于扫描谷歌IP工具的工具，提取自[checkgoogleip](https://github.com/moonshawdo/checkgoogleip)，使用说明参考：[README.md](https://github.com/xyuanmu/checkiptools/blob/master/python/README.md)
 * googleip.txt         整合后的IP段，可用于 [XX-Net](https://github.com/XX-net/XX-Net) 或者 GoGo Tester（记得保存IP段格式为 x.x.x.x/xx 并改名.ip结尾）
 * ip_range_bad.txt     包含IP段黑名单的文件，支持 checkgoogleip IP组格式，支持 # 注释
 * ip_range_origin.txt  包含原始IP段的文件，支持 checkgoogleip IP组格式，支持 # 注释，**以后只需将新IP段添加进来用 !ptools.bat 转换即可**
 * enjoy it!

## 工具预览：
![checkiptools](https://cloud.githubusercontent.com/assets/12442896/13596701/0280b8da-e54f-11e5-93c1-4dacc70ca4ae.png)
