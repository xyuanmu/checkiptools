
import os

iplist = []

if os.path.exists('ip_tmpok.txt'):
    with open('ip_tmpok.txt') as ip_tmpok:
        for x in ip_tmpok:
            sline = x.strip().split(' ')
            iplist.append(sline)
    with open('ip_json.txt', 'w') as ip_bind:
        iplist.sort(key=lambda x: int(x[1]))
        out = '"'+'", "'.join(x[0] for x in iplist if int(x[1]) < 3000)+'"' # 默认抽取3000ms以内IP，可自行修改
        print(out)
        # print(iplist)
        ip_bind.write(out)
else:
    print "\n\n      doesn't exist ip_tmpok.txt\n\n"