#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import netaddr
import ip_utils


# generate_ip_range 整合IP段去黑名单IP并排序
# test_load 计数IP数量
# ip_range_to_cidrs 将IP转换为CIDR格式

# Support format(支持的格式):
# # Comment (#后面为注释）
#
# range seperater:
# 每个范围可以用 逗号(,) 和竖线(|) 或分行进行分割
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
                bad_begin, bad_end = bad_range[bad_i]
                continue
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
                bad_begin, bad_end = bad_range[bad_i]
                break
            elif good_begin >= bad_begin and good_end > bad_end:
                # case:
                #           [   good   ]
                #     [    bad  ]
                print("cut bad ip case 3:%s - %s" % (ip_utils.ip_num_to_string(good_begin), ip_utils.ip_num_to_string(bad_end)))
                good_begin = bad_end + 1
                bad_i += 1
                bad_begin, bad_end = bad_range[bad_i]
                continue
            elif good_begin <= bad_begin and good_end >= bad_end:
                # case:
                #     [     good     ]
                #         [  bad  ]
                out_good_range.append([good_begin, bad_begin - 1])
                print("cut bad ip case 4:%s - %s" % (ip_utils.ip_num_to_string(bad_begin), ip_utils.ip_num_to_string(bad_end)))
                good_begin = bad_end + 1
                bad_i += 1
                bad_begin, bad_end = bad_range[bad_i]
                continue
            elif good_begin >= bad_begin and good_end <= bad_end:
                # case:
                #          [good]
                #      [    bad    ]
                print("cut bad ip case 5:%s - %s" % (ip_utils.ip_num_to_string(good_begin), ip_utils.ip_num_to_string(good_end)))
                break
            else:
                print("any case?")

    return out_good_range


def generate_ip_range():
    print("\nGood ip range:")
    ip_range_list = parse_range_string(input_good_range_lines)
    ip_range_list = merge_range(ip_range_list)

    print("\nBad ip range:")
    bad_range_list = parse_range_string(input_bad_ip_range_lines)
    bad_range_list = merge_range(bad_range_list)

    print("\nCut Bad ip range:")
    ip_range_list = filter_ip_range(ip_range_list, bad_range_list)

    # write out
    fd = open("googleip.txt", "w")
    for ip_range in ip_range_list:
        begin = ip_range[0]
        end = ip_range[1]
        #print ip_utils.ip_num_to_string(begin), ip_utils.ip_num_to_string(end)
        fd.write(ip_utils.ip_num_to_string(begin)+ "-" + ip_utils.ip_num_to_string(end)+"\n")

    fd.close()

generate_ip_range()


# 统计IP数量
def test_load():
    print("\nBegin test load googleip.txt")
    fd = open("googleip.txt", "r")

    amount = 0
    for line in fd.readlines():
        line = line.strip('\n')
        if len(line) == 0 or line[0] == '#':
            continue
        begin, end = ip_utils.split_ip(line)

        ip_begin_str = begin.strip().split('.')
        ip_end_str   = end.strip().split('.')

        if ip_begin_str[3] == '0':    ip_begin_str[3] = '1'
        if ip_end_str[3] == '255':    ip_end_str[3] = '254'

        str_1 = (int(ip_end_str[0]) - int(ip_begin_str[0])) * 16646144
        str_2 = (int(ip_end_str[1]) - int(ip_begin_str[1])) * 65024
        str_3 = (int(ip_end_str[2]) - int(ip_begin_str[2])) * 254
        str_4 =  int(ip_end_str[3]) - int(ip_begin_str[3])  + 1

        num = str_1 + str_2 + str_3 + str_4
        amount += num

        nbegin = ip_utils.ip_string_to_num(begin)
        nend = ip_utils.ip_string_to_num(end)
        #print ip_utils.ip_num_to_string(nbegin), ip_utils.ip_num_to_string(nend), num

    fd.close()
    print "amount ip:", amount

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
