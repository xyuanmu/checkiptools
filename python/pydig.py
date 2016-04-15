#!/usr/bin/env python
# coding: utf-8

import sys
sys.dont_write_bytecode = True

import os, re, urllib, time
from pydiglib.main import main as pydig
from pydiglib.common import LOGFILE, roll_file
from ip_utils import check_ip_valid


#默认IP，当IP被判定为无效时使用此IP代替
default_ip = '1.255.22.36'
#默认读取的URL文件，优先级大于 dig_ipfile
dig_urlfile = 'dig_url.txt'
#默认读取的IP文件，无此文件需手动输入网址或IP
dig_ipfile = 'dig_ip.txt'
#pydig日志文件，别修改
dig_logfile = LOGFILE
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


def load_ip(filename):
    ips = []
    with open(filename) as fd:
        for line in fd:
            ip = line.strip()
            ips.append(ip)
    return ips


def load_url(filename):
    ips = []
    urls = []
    with open(filename) as fd:
        for line in fd:
            url = line.strip()
            urls.append(url)
    for url in urls:
        ips += get_ip_from_url(url)
    return ips


def get_ip_from_url(url, filename=dig_ipfile):
    ips = []
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        print('download url page: %s' % url)
        html = urllib.urlopen(url).read()
    except:
        print('download url page: %s fail, try again.' % url)
        time.sleep(2)
        try:
            html = urllib.urlopen(url).read()
        except:
            print('download url page: %s fail!' % url)
            return ips
    if 'bestdns' in url:
        ips = re.compile(r'<h3>Nameserver (\d+.\d+.\d+.\d+) Details:</h3>').findall(html)
    elif 'ungefiltert-surfen' in url:
        ips = re.compile(r'searchtext=(\d+.\d+.\d+.\d+)').findall(html)
    else:
        ips = re.compile(r'(\d+.\d+.\d+.\d+)').findall(html)
    output = '\n'.join(ip for ip in ips) + '\n'
    open(filename, 'a').write(output)
    return ips


def load_ip_range(filename):
    ip_range = []
    if not os.path.isfile(filename):
        return ip_range
    with open(filename) as fd:
        for line in fd:
            range = line.strip()
            ip_range.append(range)
    return ip_range


def get_ip_range(filename, old_list=[]):
    ip_range = old_list
    if not os.path.isfile(filename):
        return ip_range
    logfile = open(filename).read()
    ips = re.compile(r'(\d+.\d+.\d+.\d+)').findall(logfile)
    for ip in ips:
        ip = ip.strip().split('.')
        range = ip[0] + '.' + ip[1] + '.' + ip[2] + '.0/24'
        ip_range.append(range)
    ip_range = list(set(ip_range))
    return ip_range


def main():
    ip = ips = ''
    if os.path.isfile(dig_urlfile):
        ips = load_url(dig_urlfile)
        roll_file(dig_urlfile)
    elif os.path.isfile(dig_ipfile):
        ips = load_ip(dig_ipfile)
    else:
        text = raw_input(u'\n请输入网址或IP：'.encode('GBK'))
        text = text.strip()
        ip = text
        if 'www' in text:
            ips = get_ip_from_url(url)
    if ips:
        for ip in ips:
            dig_ip(ip)
    elif ip:
        dig_ip(ip)
    else:
        main()
    old_list = load_ip_range(dig_iprange)
    ip_range = get_ip_range(dig_logfile, old_list)
    output = '\n'.join(x for x in ip_range) + '\n'
    open(dig_iprange, 'w').write(output)
    roll_file(dig_ipfile)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.exit(main(sys.argv))
    else:
        main()