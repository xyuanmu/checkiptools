#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import netaddr
import ip_utils


# merge_ip_range 整合IP段并排序
# test_load 计数IP数量
# ip_range_to_cidrs 将IP转换为CIDR格式

# 记得移除以下IP段
#-216.58.196.0/24
#-216.58.208.0/20
#-203.208.32.0/19


# 包含原始IP段的文件
f = open("ip_original_list.txt")
ip_str_list = f.read()

# 整合IP段并排序，源代码来自XX-Net
def merge_ip_range():
    ip_range_list = []

    ip_lines_list = re.split("\r|\n", ip_str_list)
    for iplines in ip_lines_list:
        if len(iplines) == 0 or iplines[0] == '#':
            #print "non:", iplines
            continue

        ips = re.split(",|\|", iplines)
        for line in ips:
            if len(line) == 0 or line[0] == '#':
                #print "non line:", line
                continue
            begin, end = ip_utils.split_ip(line)
            if ip_utils.check_ip_valid(begin) == 0 or ip_utils.check_ip_valid(end) == 0:
                print ("ip format is error,line:%s, begin: %s,end: %s" % (line, begin, end))
                continue
            nbegin = ip_utils.ip_string_to_num(begin)
            nend = ip_utils.ip_string_to_num(end)
            ip_range_list.append([nbegin,nend])
            #print begin, end


    ip_range_list.sort()

    # merge range
    ip_range_list_2 = []
    range_num = len(ip_range_list)

    last_begin = ip_range_list[0][0]
    last_end = ip_range_list[0][1]
    for i in range(1,range_num):
        ip_range = ip_range_list[i]

        begin = ip_range[0]
        end = ip_range[1]

        #print "now:",ip_utils.ip_num_to_string(begin), ip_utils.ip_num_to_string(end)

        if begin > last_end + 2:
            #print "add:",ip_utils.ip_num_to_string(begin), ip_utils.ip_num_to_string(end)
            ip_range_list_2.append([last_begin, last_end])
            last_begin = begin
            last_end = end
        else:
            print "merge:", ip_utils.ip_num_to_string(last_begin), ip_utils.ip_num_to_string(last_end), ip_utils.ip_num_to_string(begin), ip_utils.ip_num_to_string(end)
            if end > last_end:
                last_end = end

    ip_range_list_2.append([last_begin, last_end])


    for ip_range in ip_range_list_2:
        begin = ip_range[0]
        end = ip_range[1]
        #print ip_utils.ip_num_to_string(begin), ip_utils.ip_num_to_string(end)

    # write out
    fd = open("googleip.txt", "w")
    for ip_range in ip_range_list_2:
        begin = ip_range[0]
        end = ip_range[1]
        #print ip_utils.ip_num_to_string(begin), ip_utils.ip_num_to_string(end)
        fd.write(ip_utils.ip_num_to_string(begin)+ "-" + ip_utils.ip_num_to_string(end)+"\n")

    fd.close()

merge_ip_range()


# 计数IP数量，源代码来自XX-Net
def test_load():

    fd = open("googleip.txt", "r")
    if not fd:
        print "open googleip.txt fail."
        exit()

    amount = 0
    for line in fd.readlines():
        if len(line) == 0 or line[0] == '#':
            continue
        begin, end = ip_utils.split_ip(line)

        nbegin = ip_utils.ip_string_to_num(begin)
        nend = ip_utils.ip_string_to_num(end)

        num = nend - nbegin
        amount += num
        print ip_utils.ip_num_to_string(nbegin), ip_utils.ip_num_to_string(nend), num

    fd.close()
    print "amount:", amount

test_load()


# 转换IP范围，需要 netaddr，将 xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx 转换成 xxx.xxx.xxx.xxx/xx
def ip_range_to_cidrs():

    ip_lists = []
    ip_lists_2 = []
    ip_range = open('googleip.txt')

    for x in ip_range:
        sline = x.strip().split('-')
        ip_lists.append(sline)

    for ip_line in ip_lists:
        cidrs = netaddr.iprange_to_cidrs(ip_line[0], ip_line[1])
        for k, v in enumerate(cidrs):
            iplist = v
            ip_lists_2.append(iplist)
    #print ip_lists_2

    fd = open('googleip.ip.txt', 'w')
    for ip_cidr in ip_lists_2:
        #print ip_cidr
        fd.write(str(ip_cidr) + "\n")
    fd.close()

ip_range_to_cidrs()
