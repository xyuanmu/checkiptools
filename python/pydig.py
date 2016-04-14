#!/usr/bin/env python
# coding: utf-8

import sys
sys.dont_write_bytecode = True

import os, re, urllib, shutil
from pydiglib.main import main as pydig
from ip_utils import check_ip_valid


#默认IP，当IP被判定为无效时使用此IP代替
default_ip = '1.255.22.36'
#默认读取的IP文件，无此文件需手动输入网址或IP
dig_ipfile = 'dig_ip.txt'
#pydig日志文件
dig_logfile = 'dig_log.log'
#pydig结束后整理的IP段文件
dig_iprange = 'dig_range.txt'
#pydig结束后整理的IP段到 googleip.txt
#dig_sort_range = 1


def dig_ip(ip):
    if not check_ip_valid(ip):
        print('ip: %s is invalid, reset to default ip: %s' % (ip, default_ip))
        ip = default_ip
    print('\ndig ip: %s' % ip)
    cmd = ['', '+subnet=%s/32' % ip, '@ns1.google.com', 'www.google.com']
    pydig(cmd)


def roll_ipfile():
    for i in range(1000):
        file_name = dig_ipfile.split('.')[0] + ".%d" % i + ".txt"
        if os.path.isfile(file_name):
            continue
        print("dig_ipfile roll %s -> %s" % (dig_ipfile, file_name))
        shutil.move(dig_ipfile, file_name)
        return


def load_ip_file():
    ips = []
    with open(dig_ipfile) as fd:
        for line in fd:
            ip = line.strip()
            ips.append(ip)
    return ips


def load_ip_range():
    ip_range = []
    if not os.path.isfile(dig_iprange):
        return ip_range
    with open(dig_iprange) as fd:
        for line in fd:
            range = line.strip()
            ip_range.append(range)
    return ip_range


def get_ip_range(old_list=[]):
    ip_range = old_list
    if not os.path.isfile(dig_logfile):
        return ip_range
    logfile = open(dig_logfile).read()
    ips = re.compile(r'(\d+.\d+.\d+.\d+)').findall(logfile)
    for ip in ips:
        ip = ip.strip().split('.')
        range = ip[0] + '.' + ip[1] + '.' + ip[2] + '.0/24'
        ip_range.append(range)
    ip_range = list(set(ip_range))
    return ip_range


def main():
    ips = None
    if os.path.isfile(dig_ipfile):
        ips = load_ip_file()
    else:
        text = raw_input(u'\n请输入网址或IP：'.encode('GBK'))
        text = text.strip()
        ip = text
        if 'www' in text:
            if text.startswith('http'):
                url = text
            else:
                url = 'http://' + text
            html = urllib.urlopen(url).read()
            if 'bestdns' in url:
                ips = re.compile(r'<h3>Nameserver (\d+.\d+.\d+.\d+) Details:</h3>').findall(html)
            elif 'ungefiltert-surfen' in url:
                ips = re.compile(r'searchtext=(\d+.\d+.\d+.\d+)').findall(html)
            output = '\n'.join(ip for ip in ips) + '\n'
            open(dig_ipfile, 'w').write(output)
    if ips:
        for ip in ips:
            dig_ip(ip)
    else:
        dig_ip(ip)
    old_list = load_ip_range()
    ip_range = get_ip_range(old_list)
    output = '\n'.join(x for x in ip_range) + '\n'
    open(dig_iprange, 'w').write(output)
    roll_ipfile()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.exit(main(sys.argv))
    else:
        main()