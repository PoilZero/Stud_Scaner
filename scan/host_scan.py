from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp
import ping3

import warnings
warnings.filterwarnings('ignore')


class HostScanner:

    def __init__(self, options):
        self.protocols= options['protocols']
        self.targets  = options['targets']
        # self.portlist = options['portlist']

        self.__thread_limit = 1000
        self.__delay = 2
        self.__message = 'poil love boy'
        self.__print_lock = threading.Lock()


        print('== 启动多线程扫描')
        self.__scan_hosts()
        print('扫描结束！\n')

    def __scan_hosts(self):
        start_time = time.time()
        controllers = {
            'ICMP': self.__ICMP_controller,
            'ARP': self.__ARP_controllder
        }
        # 每个协议都运行一个单独的线程
        outputs = []
        for protocol in self.protocols:
            output = {}
            outputs.append(output)
            thread = threading.Thread(target=controllers[protocol], args=(output, ))
            thread.start()

        # 等待所有线程的线程都运行结束
        for output in outputs:
            while len(output) < len(self.targets):
                time.sleep(0.01)
                continue

        # 只要某个output是OPEN那最后去重的结果就是OPEN
        output = {}
        for one_output in outputs:
            for target in one_output:
                if output.get(target)==None:
                    output[target] = one_output[target]
                    continue
                if output[target] == '存活':
                    output[target] = '存活'

        # 打印存活主机
        print()
        print('== 扫描结果')
        flag = True
        for target in self.targets:
            if output[target]=='存活':
                print('{}: {}'.format(target, output[target]))
                flag = False
        if flag:
            print('未扫描到存活主机')

        stop_time = time.time()
        print('扫描耗时 {} 秒'.format(stop_time - start_time))
        print()
        return output


    '''
        controller enumerating ips
    '''
    def __ICMP_controller(self, output):
        target_index = 0

        while threading.activeCount() < self.__thread_limit and target_index < len(self.targets):
            thread = threading.Thread(target=self.__ICMP_scan,
                                      args=(self.targets[target_index], output))
            thread.start()
            target_index = target_index + 1
            time.sleep(0.01)

    def __ARP_controllder(self, output):
        target_index = 0

        while threading.activeCount() < self.__thread_limit and target_index < len(self.targets):
            thread = threading.Thread(target=self.__ARP_scan,
                                      args=(self.targets[target_index], output))
            thread.start()
            target_index = target_index + 1
            time.sleep(0.01)


    '''
        scan one ip
    '''
    def __ARP_scan(self, host, output):
        # 创建ARP请求数据包
        arp = ARP(pdst=host)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # 发送ARP请求并获取响应
        result = srp(packet, timeout=2, verbose=0)[0]

        # 分析响应并提取相关信息
        if len(result)>0:
            sent, received = result[0]
            mac = received.hwsrc
            with self.__print_lock:
                print(f'ARP: {host} 成功，Mac={mac}s')
            output[host] = '存活'
        else:
            output[host] = '离线'

    def __ICMP_scan(self, host, output):
        result = ping3.ping(host, src_addr=None)
        if result:
            with self.__print_lock:
                print(f'ICMP: {host} 成功，耗时{result}s')
            output[host] = '存活'
        else:
            output[host] = '离线'