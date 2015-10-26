#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import netaddr
import ip_utils

# Support format(支持的格式):
# # Comment (#后面为注释）
#
# range seperater:
# 每个范围可以用 半角逗号(,) 和竖线(|) 或分行进行分割
#
# Single rang format: (单个范围的格式)：
# "xxx.xxx.xxx-xxx.xxx-xxx" （范围格式）
# "xxx.xxx.xxx."            （前缀格式）
# "xxx.xxx.xxx.xxx/xx"      （掩码格式）
# "xxx.xxx.xxx.xxx"         （单个ip）

# 包含原始IP段的文件
input_good_range_lines = open("ip_range_origin.txt").read()

# 包含IP段黑名单的文件
input_bad_ip_range_lines = open("ip_range_bad.txt").read()


def print_range_list(ip_range_list):
    for ip_range in ip_range_list:
        begin = ip_range[0]
        end = ip_range[1]
        print ip_utils.ip_num_to_string(begin), ip_utils.ip_num_to_string(end)


def parse_range_string(input_lines):
    ip_range_list = []

    ip_lines_list = re.split("\r|\n", input_lines)
    for raw_line in ip_lines_list:
        raw_s = raw_line.split("#")
        context_line = raw_s[0]

        context_line = context_line.replace(' ', '')

        ips = re.split(",|\|", context_line)
        for line in ips:
            if len(line) == 0:
                #print "non line:", line
                continue
            begin, end = ip_utils.split_ip(line)
            if ip_utils.check_ip_valid(begin) == 0 or ip_utils.check_ip_valid(end) == 0:
                print("ip format is error,line:%s, begin: %s,end: %s" % (line, begin, end))
                continue
            nbegin = ip_utils.ip_string_to_num(begin)
            nend = ip_utils.ip_string_to_num(end)
            ip_range_list.append([nbegin,nend])
            #print begin, end

    ip_range_list.sort()

    return ip_range_list


def merge_range(input_ip_range_list):
    output_ip_range_list = []
    range_num = len(input_ip_range_list)

    last_begin = input_ip_range_list[0][0]
    last_end = input_ip_range_list[0][1]
    for i in range(1,range_num):
        ip_range = input_ip_range_list[i]
        begin = ip_range[0]
        end = ip_range[1]

        #print "now:",ip_utils.ip_num_to_string(begin), ip_utils.ip_num_to_string(end)

        if begin > last_end + 1:
            #print "add:",ip_utils.ip_num_to_string(begin), ip_utils.ip_num_to_string(end)
            output_ip_range_list.append([last_begin, last_end])
            last_begin = begin
            last_end = end
        else:
            print "merge:", ip_utils.ip_num_to_string(last_begin), ip_utils.ip_num_to_string(last_end), ip_utils.ip_num_to_string(begin), ip_utils.ip_num_to_string(end)
            if end > last_end:
                last_end = end

    output_ip_range_list.append([last_begin, last_end])

    return output_ip_range_list


def filter_ip_range(good_range, bad_range):
    out_good_range = []
    bad_i = 0

    bad_begin, bad_end = bad_range[bad_i]

    for good_begin, good_end in good_range:
        while True:
            if good_begin > good_end:
                print("bad good ip range when filter:%s-%s"  % (ip_utils.ip_num_to_string(good_begin), ip_utils.ip_num_to_string(good_end)))
                break
            if good_end < bad_begin:
                # case:
                #     [  good  ]
                #                   [  bad  ]
                out_good_range.append([good_begin, good_end])
                break
            elif bad_end < good_begin:
                # case:
                #                   [  good  ]
                #     [   bad   ]
                bad_i += 1
                if bad_i < len(bad_range):
                    bad_begin, bad_end = bad_range[bad_i]
                    continue
                else:
                    break
            elif good_begin <= bad_begin and good_end <= bad_end:
                # case:
                #     [   good    ]
                #           [   bad   ]
                print("cut bad ip case 1:%s - %s" % (ip_utils.ip_num_to_string(bad_begin), ip_utils.ip_num_to_string(good_end)))
                if bad_begin - 1 > good_begin:
                    out_good_range.append([good_begin, bad_begin - 1])
                break
            elif good_begin >= bad_begin and good_end == bad_end:
                # case:
                #           [   good   ]
                #     [      bad       ]
                print("cut bad ip case 2:%s - %s" % (ip_utils.ip_num_to_string(good_begin), ip_utils.ip_num_to_string(bad_end)))

                bad_i += 1
                if bad_i < len(bad_range):
                    bad_begin, bad_end = bad_range[bad_i]
                break
            elif good_begin >= bad_begin and good_end > bad_end:
                # case:
                #           [   good   ]
                #     [    bad  ]
                print("cut bad ip case 3:%s - %s" % (ip_utils.ip_num_to_string(good_begin), ip_utils.ip_num_to_string(bad_end)))
                good_begin = bad_end + 1
                bad_i += 1
                if bad_i < len(bad_range):
                    bad_begin, bad_end = bad_range[bad_i]
                    continue
                else:
                    break
            elif good_begin <= bad_begin and good_end >= bad_end:
                # case:
                #     [     good     ]
                #         [  bad  ]
                out_good_range.append([good_begin, bad_begin - 1])
                print("cut bad ip case 4:%s - %s" % (ip_utils.ip_num_to_string(bad_begin), ip_utils.ip_num_to_string(bad_end)))
                good_begin = bad_end + 1
                bad_i += 1
                if bad_i < len(bad_range):
                    bad_begin, bad_end = bad_range[bad_i]
                    continue
                else:
                    break
            elif good_begin >= bad_begin and good_end <= bad_end:
                # case:
                #          [good]
                #      [    bad    ]
                print("cut bad ip case 5:%s - %s" % (ip_utils.ip_num_to_string(good_begin), ip_utils.ip_num_to_string(good_end)))
                break
            else:
                print("any case?")

    return out_good_range


# 整合IP段去黑名单IP段并排序
def generate_ip_range():
    print("\nMerge Good ip range:")
    ip_range_list = parse_range_string(input_good_range_lines)
    ip_range_list = merge_range(ip_range_list)

    print("\nMerge Bad ip range:")
    bad_range_list = parse_range_string(input_bad_ip_range_lines)
    bad_range_list = merge_range(bad_range_list)

    print("\nCut Bad ip range:")
    ip_range_list = filter_ip_range(ip_range_list, bad_range_list)

    # write out
    ip_out_lists = []
    for ip_range in ip_range_list:
        begin = ip_range[0]
        end = ip_range[1]
        ip_out_lists.append(ip_utils.ip_num_to_string(begin) + "-" + ip_utils.ip_num_to_string(end))
    ip_out_lists = ip_range_to_cidr(ip_out_lists)
    open('googleip.txt', 'w').write('\n'.join(x for x in ip_out_lists))


def test_ip_num(begin, end):
    ip_begin_str = begin.strip().split('.')
    ip_end_str   = end.strip().split('.')

    if ip_begin_str[3] == '0':    ip_begin_str[3] = '1'
    if ip_end_str[3] == '255':    ip_end_str[3] = '254'

    str_1 = (int(ip_end_str[0]) - int(ip_begin_str[0])) * 16646144
    str_2 = (int(ip_end_str[1]) - int(ip_begin_str[1])) * 65024
    str_3 = (int(ip_end_str[2]) - int(ip_begin_str[2])) * 254
    str_4 =  int(ip_end_str[3]) - int(ip_begin_str[3])  + 1

    num = str_1 + str_2 + str_3 + str_4
    return num


def test_ip_amount(ip_lists):
    amount = 0
    for ip in ip_lists:
        if len(ip) == 0 or ip[0] == '#':
            continue
        begin, end = ip_utils.split_ip(ip)
        num = test_ip_num(begin, end)
        amount += num
        print begin, end, num
    print "amount ip:", amount, '\n'
    return amount


# 统计IP数量，超过1KW自动分割
def test_load():
    print("\nBegin test load googleip.txt")
    fd = open("googleip.txt", "r")

    i = 1
    amount = 0
    ip_rip = 10000000    # 以1KW个IP分割IP段
    ip_lists = []

    ip_range_list = re.split("\r|\n", fd.read())
    ip_amount = test_ip_amount(ip_range_list)

    for line in ip_range_list:
        if len(line) == 0 or line[0] == '#':
            continue
        begin, end = ip_utils.split_ip(line)
        num = test_ip_num(begin, end)
        amount += num
        ip_lists.append(line)

        #print begin, end, num
        filename = 'googleip-%03d.txt' % i
        if amount > i*ip_rip:
            print "ip amount over %s" % (i*ip_rip)
            ip_lists = ip_range_to_cidr(ip_lists)
            open(filename,'w').write('\n'.join(x for x in ip_lists))
            i += 1
            ip_lists = []
        elif amount == ip_amount:
            print "ip amount below %s" % (i*ip_rip), '\n'
            ip_lists = ip_range_to_cidr(ip_lists)
            if amount > ip_rip : open(filename,'w').write('\n'.join(x for x in ip_lists))
        continue
    fd.close()


# 转换IP范围，需要 netaddr，将IP转换为CIDR格式
def ip_range_to_cidr(ip_str_lists):
    ip_cidr_network = []
    ip_cidr_lists = []
    for ip_str in ip_str_lists:
        begin, end = ip_utils.split_ip(ip_str)
        cidrs = netaddr.iprange_to_cidrs(begin, end)
        for k, v in enumerate(cidrs):
            ip = v
            ip_cidr_network.append(ip)
    for ip_cidr in ip_cidr_network:
        ip_cidr_lists.append(str(ip_cidr))
    return ip_cidr_lists


# convert_ip_tmpok(延时, 格式) 转换ip_tmpok.txt 并剔除重复IP
def convert_ip_tmpok(timeout, format):
    line_list = []
    ip_list = []
    new_line_list = []
    if os.path.exists('ip_tmpok.txt'):
        with open('ip_tmpok.txt') as ip_tmpok:
            for x in ip_tmpok:
                sline = x.strip().split(' ')
                if sline[1].startswith('NA_'): sline[1] = sline[1].lstrip('NA_')
                line_list.append(sline)
        line_list.sort(key=lambda x: int(x[1]))
        for line in line_list:
            if line[0] not in ip_list:
                ip_list.append(line[0])
                new_line_list.append(line)
        if format == 1:
            ip_out = 'ip_bind.txt'
        elif format == 2:
            ip_out = 'ip_json.txt'
        elif format == 3:
            ip_out = 'ip_xxnet.txt'
        with open(ip_out, 'w') as ip_output:
            if format == 1:
                out = '|'.join(x[0] for x in new_line_list if int(x[1]) < timeout)
            elif format == 2:
                out = '"'+'", "'.join(x[0] for x in new_line_list if int(x[1]) < timeout)+'"'
            elif format == 3:
                out = '\n'.join(x[0] + " " + x[2] + " gws " + x[1] + " 0" for x in new_line_list)
            print(out + '\n')
            ip_output.write(out)
    else:
        print "\n    doesn't exist ip_tmpok.txt\n"


def convertip(iplist):
    if iplist == "": return
    fd = open('ip_output.txt', 'w')
    iplist = iplist.replace(' ','')
    if '|' in iplist:
        out = '"' + iplist.replace('|', '", "') + '"'
    else:
        ip_str = []
        ip_str = iplist.replace('"','').split(',')
        out = '|'.join(x for x in ip_str)
    print('\n' + out + '\n')
    fd.write(out)
    fd.close()


# 选项
def main():
    cmd = raw_input(
    """
请选择需要处理的操作, 输入对应的数字并按下回车:

 1. 提取 ip_tmpok.txt 中的IP, 并生成 ip_bind.txt, 用｜分隔

 2. 提取 ip_tmpok.txt 中的IP, 并生成 ip_json.txt, json格式

 3. 转换 ip_tmpok.txt 中的IP, 为XX-Net格式, 并生成 ip_xxnet.txt

 4. 整合 ip_range_origin.txt  中的IP段, 并生成 googleip.txt

 5. 统计 googleip.txt 中的IP数量, 超过1KW自动分割

 6. 同时执行4、5两条命令

 7. IP格式互转 GoAgent <==> GoProxy, 并生成 ip_output.txt

    """
    )
    cmd = cmd.replace(" ","")
    if cmd == '1' or cmd == '2':
        timeout = raw_input("""
请输入延时（不用单位）, 默认2000毫秒: """
        )
        if timeout == '': timeout = 2000
        if cmd == '1':
            convert_ip_tmpok(int(timeout), 1)
        elif cmd == '2':
            convert_ip_tmpok(int(timeout), 2)
    elif cmd == '3':
        convert_ip_tmpok(0,3)
    elif cmd == '4':
        generate_ip_range()
    elif cmd == '5':
        test_load()
    elif cmd == '6':
        generate_ip_range()
        test_load()
    elif cmd == '7':
        iplist = raw_input("""
请输入需要转换的IP, 可使用右键->粘贴: 

"""
        )
        convertip(iplist)
    else:
        main()

if __name__ == '__main__':
    main()
