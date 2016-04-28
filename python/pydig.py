#!/usr/bin/env python
# coding: utf-8

import sys
sys.dont_write_bytecode = True

import os, re, time, threading
from urllib2 import Request, urlopen
from pydig.main import main as pydig
from pydig.common import LOGFILE, roll_file
from ip_utils import check_ip_valid
from iptools import generate_ip_range


#默认IP，当IP被判定为无效时使用此IP代替
default_ip = '1.255.22.36'
#默认读取的URL文件，优先级大于 dig_ipfile
dig_urlfile = 'dig_url.txt'
#默认读取的IP文件，无此文件需手动输入网址或IP
dig_ipfile = 'dig_ip.txt'
#pydig日志文件，别修改
dig_logfile = LOGFILE
#pydig失败的IP文件
dig_error = 'dig_tmperror.txt'
#pydig成功的IP文件
dig_finished = 'dig_tmpfinished.txt'
#pydig结束后整理的IP段文件
dig_iprange = 'dig_range.txt'
#pydig最大线程数
dig_max_threads = 50
#pydig结束后重新dig一次dig_error中的IP
dig_redig_error = 1
#pydig结束后整合IP段到 googleip.txt
dig_sort_range = 0

HEADER = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1; rv:43.0) Gecko/20100101 Firefox/43.0'}


def dig_ip(ip):
    if not check_ip_valid(ip):
        print('ip: %s is invalid, reset to default ip: %s' % (ip, default_ip))
        ip = default_ip
    print('\ndig ip: %s' % ip)
    cmd = ['1', '+subnet=%s/32' % ip, '@ns1.google.com', 'www.google.com']
    code = pydig(cmd)
    if code == 502:
        open(dig_error, "a").write(ip + "\n")
    else:
        open(dig_finished, "a").write(ip + "\n")


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
        req = Request(url, headers=HEADER)
        html = urlopen(req, timeout=5).read()
    except:
        print('download url page: %s fail, try again.' % url)
        time.sleep(2)
        try:
            req = Request(url, headers=HEADER)
            html = urlopen(req, timeout=5).read()
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


class DIG():
    def __init__(self, ips, finishedip, max_thread_num):
        self.dig_lock = threading.Lock()
        self.dig_ips = ips
        self.dig_finishedip = finishedip
        self.dig_max_thread_num = max_thread_num
        self.dig_thread_num = 0
        self.dig_ipdict = []

    def dig_ip_worker(self):
        for ip in self.dig_ips:
            if len(self.dig_ipdict) == len(self.dig_ips):
                break
            if ip in self.dig_ipdict or ip in self.dig_finishedip:
                continue
            self.dig_ipdict.append(ip)
            if not check_ip_valid(ip):
                print('ip: %s is invalid, reset to default ip: %s' % (ip, default_ip))
                ip = default_ip
            print('\ndig ip: %s' % ip)
            cmd = ['1', '+subnet=%s/32' % ip, '@ns1.google.com', 'www.google.com']
            code = pydig(cmd)
            self.dig_lock.acquire()
            if code == 502:
                open(dig_error, "a").write(ip + "\n")
            else:
                open(dig_finished, "a").write(ip + "\n")
            self.dig_lock.release()
        print 'dig_ip_worker exit'

    def start_dig(self):
        new_thread_num = self.dig_max_thread_num - self.dig_thread_num
        if new_thread_num < 1:
            return
        for i in range(0, new_thread_num):
            self.dig_lock.acquire()
            self.dig_thread_num += 1
            self.dig_lock.release()
            d = threading.Thread(target = self.dig_ip_worker)
            d.start()
            time.sleep(0.5)


def main():
    ip = ''
    ips = []
    finishedip = []
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

    if os.path.isfile(dig_finished):
        finishedip = load_ip(dig_finished)
    if ips:
        dig = DIG(ips, finishedip, dig_max_threads)
        dig.start_dig()
    elif ip:
        dig_ip(ip)
    else:
        main()

    if dig_redig_error and os.path.isfile(dig_error):
        print '\nredig ip from %s' % dig_error
        errorip = load_ip(dig_error)
        errorip = list(set(errorip))
        roll_file(dig_error)
        dig = DIG(errorip, finishedip, dig_max_threads)
        dig.start_dig()

    old_list = load_ip_range(dig_iprange)
    ip_range = get_ip_range(dig_logfile, old_list)
    output = '\n'.join(x for x in ip_range) + '\n'
    open(dig_iprange, 'w').write(output)
    roll_file(dig_ipfile)
    print 'dig finished!'

    if dig_sort_range:
        print 'begin sort ip and merge into googleip.txt'
        good_range = open('googleip.txt').read()
        good_range += open(dig_iprange).read()
        generate_ip_range(2, good_range)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.exit(main(sys.argv))
    else:
        main()