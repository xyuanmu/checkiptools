# -*- coding: utf-8 -*-

import re
import subprocess
import sys
import urllib2
import math
import time
import os.path
import ip_utils

fdir = os.path.dirname(os.path.abspath(__file__))


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
        if begin > last_end + 2:
            #print "add:",ip_utils.ip_num_to_string(begin), ip_utils.ip_num_to_string(end)
            output_ip_range_list.append(ip_utils.ip_num_to_string(last_begin)+ "-" + ip_utils.ip_num_to_string(last_end))
            last_begin = begin
            last_end = end
        else:
            #print "merge:", ip_utils.ip_num_to_string(last_begin), ip_utils.ip_num_to_string(last_end), ip_utils.ip_num_to_string(begin), ip_utils.ip_num_to_string(end)
            if end > last_end:
                last_end = end
    output_ip_range_list.append(ip_utils.ip_num_to_string(last_begin)+ "-" + ip_utils.ip_num_to_string(last_end))
    return output_ip_range_list


def download_apic(filename):
    url = 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
    try:
        data = subprocess.check_output(['wget', url, '-O-'])
    except (OSError, AttributeError):
        print >> sys.stderr, "Fetching data from apnic.net, "\
                             "it might take a few minutes, please wait...\n"
        data = urllib2.urlopen(url).read()
    with open(filename, "w") as f:
        f.write(data)
    return data


def generage_range_from_apnic(input,feature):
    if feature == 2: cnregex = re.compile(r'^apnic\|(?:cn|hk|mo)\|ipv4\|[\d\.]+\|\d+\|\d+\|a\w*$', re.I | re.M )
    else: cnregex = re.compile(r'^apnic\|(?:cn)\|ipv4\|[\d\.]+\|\d+\|\d+\|a\w*$', re.I | re.M )
    cndata = cnregex.findall(input)
    results = []
    for item in cndata:
        unit_items = item.split('|')
        starting_ip = unit_items[3]
        num_ip = int(unit_items[4])
        cidr = 32 - int(math.log(num_ip, 2))
        results.append("%s/%s" % (starting_ip, cidr))
    return "\n".join(results) + "\n"

def load_bad_ip_range(feature):
    filename = "delegated-apnic-latest.txt"
    apnic_file = os.path.join(fdir, filename)
    if not os.path.isfile(apnic_file):
        download_apic(apnic_file)
    with open(apnic_file) as inf:
        apnic_lines = inf.read()
    bad_ip_range_lines = generage_range_from_apnic(apnic_lines,feature)
    # 添加自定义IP黑名单
    input_bad_ip_range_lines = open("ip_bad.txt").read()
    return bad_ip_range_lines + input_bad_ip_range_lines


def generate_ip_range(feature):
    # load input good ip range
    file_name = "ip_range_bad.txt" if feature == 1 else "ip_range_bad2.txt"
    bad_ip_range = load_bad_ip_range(feature)
    ip_range_list = parse_range_string(bad_ip_range)
    ip_range_list = merge_range(ip_range_list)
    # test ip amount
    ip_amount = test_ip_amount(file_name,ip_range_list)
    # write out
    output_file = os.path.join(fdir, file_name)
    fd = open(output_file, "w")
    local = 'cn' if feature == 1 else 'cn|hk|mo'
    update_time = time.strftime('%Y-%m-%d %H:%M',time.localtime(time.time()))
    fd.write("#include %s ip range and bad ip range, update time: %s, amount ip: %s" % (local, update_time, ip_amount) + "\n")
    fd.write("\n".join(x for x in ip_range_list))
    fd.close()


def test_ip_amount(file_name,ip_lists):
    amount = 0
    for ip in ip_lists:
        begin, end = ip_utils.split_ip(ip)
        ip_begin_str = begin.split('.')
        ip_end_str   = end.split('.')
        if ip_begin_str[3] == '0':    ip_begin_str[3] = '1'
        if ip_end_str[3] == '255':    ip_end_str[3] = '254'
        str_1 = (int(ip_end_str[0]) - int(ip_begin_str[0])) * 16646144
        str_2 = (int(ip_end_str[1]) - int(ip_begin_str[1])) * 65024
        str_3 = (int(ip_end_str[2]) - int(ip_begin_str[2])) * 254
        str_4 =  int(ip_end_str[3]) - int(ip_begin_str[3])  + 1
        num = str_1 + str_2 + str_3 + str_4
        amount += num
        #print begin, end, num
    amount = format(amount, ',')
    print "%s amount ip: %s \n" % (file_name, amount)
    return amount


if __name__ == "__main__":
    generate_ip_range(1)
    # 包含香港澳门的IP黑名单
    # generate_ip_range(2)