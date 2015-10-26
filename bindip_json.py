
import os

if os.path.exists('ip_tmpok.txt'):
    line_list = []
    ip_list = []
    new_line_list = []
    with open('ip_tmpok.txt') as ip_tmpok:
        for x in ip_tmpok:
            sline = x.strip().split(' ')
            if sline[1].startswith("NA_"): sline[1] = sline[1].lstrip('NA_')
            line_list.append(sline)
    line_list.sort(key=lambda x: int(x[1]))
    for line in line_list:
        if line[0] not in ip_list:
            ip_list.append(line[0])
            new_line_list.append(line)
    with open('ip_json.txt', 'w') as ip_bind:
        out = '"'+'", "'.join(x[0] for x in new_line_list if int(x[1]) < 2000)+'"' # 默认抽取2000ms以内IP，可自行修改
        print(out)
        # print(iplist)
        ip_bind.write(out)
else:
    print "\n\n      doesn't exist ip_tmpok.txt\n\n"