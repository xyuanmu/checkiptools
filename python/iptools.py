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
# Single range format: (单个范围的格式)：
# "xxx.xxx.xxx-xxx.xxx-xxx" （范围格式）
# "xxx.xxx.xxx."            （前缀格式）
# "xxx.xxx.xxx.xxx/xx"      （掩码格式）
# "xxx.xxx.xxx.xxx"         （单个ip）

# 包含原始IP段的文件
ip_range_origin = "ip_range_origin.txt"
input_good_range_lines = open(ip_range_origin).read()

# 包含IP段黑名单的文件
ip_range_bad = "ip_range_bad.txt"
input_bad_ip_range_lines = open(ip_range_bad).read()
input_bad_ip_range_lines2 = "\n"# + open("ip_range_bad2.txt").read()
input_bad_ip_range_lines = input_bad_ip_range_lines + input_bad_ip_range_lines2

# IP转换后输出的文件
ip_output_file = "ip_output.txt"

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
                    out_good_range.append([good_begin, good_end])
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
                    out_good_range.append([bad_end + 1, good_end])
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
                    out_good_range.append([bad_end + 1, good_end])
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
    feature = raw_input( u"\nIP段格式: 1、x.x.x.x-x.x.x.x   2、x.x.x.x/xx ".encode("GBK") )
    if feature == '': feature = 1
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
    if int(feature) == 2: ip_out_lists = ip_range_to_cidr(ip_out_lists)
    open('googleip.txt', 'w').write('\n'.join(x for x in ip_out_lists) + '\n')


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
        begin, end = ip_utils.split_ip(ip)
        num = test_ip_num(begin, end)
        amount += num
        #print begin, end, num
    print "amount ip: %s \n" % format(amount, ',')
    return amount


# 统计IP数量，超过1KW提示分割
def test_load():
    print("\nBegin test load googleip.txt")
    fd = open('googleip.txt')

    i = 1
    amount = 0
    ip_rip = 10000000    # 以1KW个IP分割IP段
    ip_lists = []
    ip_range_list = []

    ip_range = re.split("\r|\n", fd.read())
    for ip_line in ip_range:
        if len(ip_line) == 0 or ip_line[0] == '#':
            continue
        ip_line = ip_line.replace(' ', '')
        ips = ip_line.split("|")
        for ip in ips:
            if len(ip) == 0:
                continue
            ip_range_list.append(ip)
    fd.close()

    ip_amount = test_ip_amount(ip_range_list)
    if ip_amount > ip_rip:
        rip = raw_input( u"IP数量超过%s，是否分割IP段: 1.是 2.否 ".encode("GBK") % format(i*ip_rip, ',') )
    else:
        return
    rip = rip.strip()
    if rip == '2' or rip != '1':
        print
        return

    for line in ip_range_list:
        begin, end = ip_utils.split_ip(line)
        num = test_ip_num(begin, end)
        amount += num
        ip_lists.append(line)

        filename = 'googleip-%03d.txt' % i
        if amount > i*ip_rip:
            print "ip amount over %s" % format(i*ip_rip, ',')
            ip_lists = ip_range_to_cidr(ip_lists)
            open(filename,'w').write('\n'.join(x for x in ip_lists) + '\n')
            i += 1
            ip_lists = []
        elif amount == ip_amount:
            print "ip amount below %s" % format(i*ip_rip, ','), '\n'
            ip_lists = ip_range_to_cidr(ip_lists)
            if amount > ip_rip : open(filename,'w').write('\n'.join(x for x in ip_lists) + '\n')


# 转换IP范围，需要 netaddr，将IP转换为CIDR格式
def ip_range_to_cidr(ip_str_lists):
    ip_cidr_network = []
    ip_cidr_lists = []
    for ip_str in ip_str_lists:
        begin, end = ip_utils.split_ip(ip_str)
        cidrs = netaddr.iprange_to_cidrs(begin, end)
        for ip in cidrs:
            ip_cidr_network.append(ip)
    for ip_cidr in ip_cidr_network:
        ip_cidr_lists.append(str(ip_cidr))
    return ip_cidr_lists


# convert_ip_tmpok(延时, 格式, 有效IP数) 转换/提取 ip_tmpok.txt
def convert_ip_tmpok(timeout, format, good_ip_num=0):
    with open('ip_tmpok.txt') as ip_tmpok:
        new_line_list = sort_tmpok(ip_tmpok, format, timeout)
    if format == 1:
        out = '|'.join(x for x in new_line_list)
        out+= '\n\n"'+'", "'.join(x for x in new_line_list)+'"'
    elif format == 2:
        new_ip_range = extract_ip(new_line_list, good_ip_num)
        out = '\n'.join(x for x in new_ip_range) if new_ip_range else ''
    elif format == 3:
        out = '\n'.join(x[0] + " " + x[2] + " gws " + x[1] + " 0" for x in new_line_list)
    if len(out) > 6:
        print(out + "\n")
        open(ip_output_file, 'w').write(out + '\n')
    else:
        print "\n    No enough ip! \n"


# extract_ip(需要提取的IP数组, 有效IP数)
def extract_ip(filter_ip, good_ip_num):
    if len(filter_ip) < 1:
        return False
    ip_lists = []
    ip_range = []
    for ip in filter_ip:
        ip = ip.split('.')
        ip_lists.append(ip)
    if good_ip_num == 1:
        for ip in ip_lists:
            ip = ip[0] + "." + ip[1] + "." + ip[2] + ".0/24"
            ip_range.append(ip)
    else:
        i = d = 1
        for ip in ip_lists:
            if i == 1: last_ip = ip
            if not i == 1:
                if ip[0] == last_ip[0] and ip[1] == last_ip[1] and ip[2] == last_ip[2]:
                    d += 1
                    if d >= good_ip_num:
                        ip = ip[0] + "." + ip[1] + "." + ip[2] + ".0/24"
                        ip_range.append(ip)
                        d = 1
                else:
                    last_ip = ip
                    d = 1
            i += 1
    new_ip_range = list(set(ip_range))
    new_ip_range.sort(key=ip_range.index)
    #print new_ip_range
    return new_ip_range


# sort_tmpok(ip_tmpok文件内容, 格式, 延时) 对ip_tmpok文件内容进行整理和排序，并剔除重复IP
def sort_tmpok(ip_tmpok, format, timeout=0):
    line_list = []
    ip_list = []
    new_line_list = []
    for line in ip_tmpok:
        line = line.replace('NA_', '')
        if '[INFO] Add' in line:
            line = line.replace('time:', '')
            line = line.replace('CN:', '')
            nline = line.strip().split(' ')
            sline = [nline[6], nline[7], nline[8], 'gws']
        else:
            sline = line.strip().split(' ')
        if sline[3].isdigit():
            sline[2] = sline[1]
            sline[1] = sline[3]
        line_list.append(sline)
    if format == 2:   # 提取IP段使用IP来进行排序而不是延时
        line_list.sort(key=lambda x: ( int(x[0].split('.')[0]), int(x[0].split('.')[1]), int(x[0].split('.')[2]), int(x[0].split('.')[3]) ))
    else:
        line_list.sort(key=lambda x: int(x[1]))
    for line in line_list:
        if line[0] not in ip_list:
            ip_list.append(line[0])
            if format == 3:   # 转换为XX-Net格式需要返回整行数组
                new_line_list.append(line)
            elif format == 4:   # 整合tmp文件夹的ip_tmpok文件需要返回整行内容
                new_line_list.append(' '.join(x for x in line))
            else:
                if int(line[1]) < timeout: new_line_list.append(line[0])
    return new_line_list


def convertip(iplist):
    if iplist == "": return
    fd = open(ip_output_file, 'w')
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


# 整合tmp目录下所有的可用IP
def integrate_tmpok():
    tmpdir = "tmp/"
    files  = os.listdir(tmpdir)
    files.sort()
    ip_tmpok_lists = []
    for item in files:
        if "ip_tmpok-" in item:
            i = re.findall(r'([0-9]+)',item)[0]
            ip_tmpok_lists += open("tmp/ip_tmpok-%s.txt" % i).readlines()
    if len(ip_tmpok_lists) < 3:
        print "\n    doesn't find any ip_tmpok in tmp/ \n"
    else:
        #print ip_tmpok_lists
        try:
            ip_tmpok_lists += open("ip_tmpok.txt").readlines()
        except:
            pass
        out_lists = sort_tmpok(ip_tmpok_lists, 4)
        output = '\n'.join(x for x in out_lists)
        print output + "\n"
        open("ip_tmpok.txt", "w").write(output + '\n')


# 选项
def main():
    add_tmpok = "   "
    if os.path.exists("tmp/"):
        add_tmpok = u"8. 整合tmp目录下的可用IP到 ip_tmpok.txt \n\n    ".encode("GBK")
    cmd = raw_input(
    u"""
请选择需要处理的操作, 输入对应的数字并按下回车:

 1. 提取 ip_tmpok.txt 中的IP, 用｜分隔以及 json 格式, 并生成 {0}

 2. 提取 ip_tmpok.txt 中有效IP的IP段, 并生成 {0}

 3. 转换 ip_tmpok.txt 中的IP为 XX-Net 格式, 并生成 {0}

 4. 整合 ip_range_origin.txt 中的IP段, 并生成 googleip.txt

 5. 统计 googleip.txt 中的IP数量, 超过1KW提示分割

 6. 同时执行4、5两条命令

 7. IP格式互转 GoAgent <==> GoProxy, 并生成 {0}

 """.encode("GBK").format(ip_output_file) + add_tmpok
    )
    cmd = cmd.replace(" ","")
    if cmd == '1' or cmd == '2' or cmd == '3':
        if not os.path.isfile('ip_tmpok.txt'):
            print "\n    ip_tmpok.txt doesn't exist\n"
            return
    if cmd == '1':
        timeout = raw_input( u"\n请输入IP延时（不用单位）, 默认2000毫秒: ".encode("GBK") )
        if timeout == '': timeout = 2000
        convert_ip_tmpok(int(timeout), 1)
    elif cmd == '2':
        timeout = raw_input( u"\n提取IP的延时范围（不用单位）, 默认2000毫秒: ".encode("GBK") )
        if timeout == '': timeout = 2000
        good_ip_num = raw_input( u"\n在/24范围内有效IP数, 输入1提取所有/24的IP段: ".encode("GBK") )
        if good_ip_num == '': good_ip_num = 1
        convert_ip_tmpok(int(timeout), 2, int(good_ip_num))
    elif cmd == '3':
        convert_ip_tmpok(0, 3)
    elif cmd == '4':
        generate_ip_range()
    elif cmd == '5':
        test_load()
    elif cmd == '6':
        generate_ip_range()
        test_load()
    elif cmd == '7':
        iplist = raw_input( u"\n请输入需要转换的IP, 可使用右键->粘贴: \n".encode("GBK") )
        convertip(iplist)
    elif cmd == '8':
        integrate_tmpok()
    else:
        main()

if __name__ == '__main__':
    main()
