import argparse
from utils.address_resolver import resolve_address,resolve_address_file
from utils.port_list import *

# 创建参数解析器对象
parser = argparse.ArgumentParser(description='扫描器参数解析器')

# 定义互斥参数组1
protocol_group = parser.add_mutually_exclusive_group(required=True)
protocol_group.add_argument('-hostscan', '-hs', nargs='+', choices=['ICMP', 'ARP'], help='要扫描的协议类型')
protocol_group.add_argument('-portscan', '-ps', nargs='+', choices=['TCP', 'UDP', 'FIN', 'SYN', 'ACK', 'XMAS'], help='要扫描的协议类型')

# 定义互斥参数组2
target_group = parser.add_mutually_exclusive_group(required=True)
target_group.add_argument('-addr', '-a', help='要扫描的IP地址或域名（可以包含网段）')
target_group.add_argument('-file', '-f', help='包含要扫描的IP地址或域名的文件路径')

# 定义可选参数
parser.add_argument('-portlist', '-pl', default='top50', help='要扫描的端口列表top50/top100/top1000/自定义文件路径，默认为top50')


# 解析参数
args = parser.parse_args()

'''
    数据预处理：
        process_type 显式区分hostscan和portscan，以便后续使用
        protocols 用于存储协议类型list
        targets 用于存储解析后的所有IP
        portlist 用于存储端口列表
'''
def resolve_port_file(file_path):
    port_list = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    port = int(line)
                except:
                    continue
                if port not in port_list:
                    port_list.append(port)
    return port_list

options = {'process_type': None, 'protocols': None, 'targets': None, 'portlist': None}
# 输出解析结果并保存options
if args.hostscan:
    options['process_type'] = 'hostscan'
    options['protocols'] = args.hostscan
    print('扫描模式:', options['process_type'])
    print('扫描以下协议类型：', options['protocols'])
elif args.portscan:
    options['process_type'] = 'portscan'
    options['protocols'] = args.portscan
    if args.portlist not in ['top50', 'top100', 'top1000']:
        print('扫描以下文件中包含的端口号：', args.portlist)
        options['portlist'] = resolve_port_file(args.portlist)
    else:
        options['portlist'] = {
            'top50': port_list_top_50
            , 'top100': port_list_top_100
            , 'top1000': port_list_top_1000
        }[args.portlist]
    print('扫描端口号：', options['portlist'])
    print('扫描模式:', options['process_type'])
    print('扫描以下协议类型：', options['protocols'])
if args.addr:
    print('扫描以下IP地址或域名：', args.addr)
    options['targets'] = resolve_address(args.addr)
    print('IP地址或域名已解析:', options['targets'])
elif args.file:
    print('扫描以下文件中包含的IP地址或域名：', args.file)
    options['targets'] = resolve_address_file(args.file)
    print('IP地址或域名已解析:', options['targets'])
print()