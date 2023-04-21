# -*- coding: utf-8 -*-
import socket
import threading
import time

try:
    from scapy.all import IP, TCP, sr1, RandShort, UDP
except ImportError:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.sendrecv import sr1
    from scapy.volatile import RandShort

import warnings
warnings.filterwarnings('ignore')

from ui.brute_ui import BruteUI
from brute.brute import Brute

class PortScanner:

    def __init__(self, options):
        self.protocols= options['protocols']
        self.targets  = options['targets']
        self.portlist = options['portlist']

        self.__thread_limit = 1000
        self.__delay = 10
        self.__message = 'poil love boy'.encode('utf-8')
        self.__print_lock = threading.Lock()


        print('== 启动多线程扫描')
        for ip in self.targets:
            self.__scan_ports(ip, self.__delay, self.__message)
        print('扫描结束！\n')

    def __scan_ports(self, ip, delay, message):
        print('= 正在扫描主机 {}'.format(ip))
        start_time = time.time()
        controllers = {
            'TCP': self.__Tcpscan_ports_controller,
            'FIN': self.__Finscan_ports_controller,
            'SYN': self.__Synscan_ports_controller,
            'ACK': self.__Ackscan_ports_controller,
            'UDP': self.__Udpscan_ports_controller,
            'XMAS': self.__XMas_ports_controller
        }
        # 每个协议都运行一个单独的线程
        outputs = []
        for protocol in self.protocols:
            output = {}
            outputs.append(output)
            thread = threading.Thread(target=controllers[protocol], args=(ip, delay, output, message))
            thread.start()

        # 等待所有线程的线程都运行结束
        for output in outputs:
            while len(output) < len(self.portlist):
                time.sleep(0.01)
                continue

        # 只要某个output是OPEN那最后去重的结果就是OPEN
        output = {}
        for one_output in outputs:
            for port in one_output:
                if output.get(port)==None:
                    output[port] = one_output[port]
                elif one_output[port]=='开放':
                    output[port] = '开放'

        # 打印端口
        print()
        print('== 扫描结果')
        flag = True
        for port in self.portlist:
            if output[port]=='开放':
                print('{}: {}'.format(port, output[port]))
                flag = False
        if flag:
            print('未扫描到开放端口')

        stop_time = time.time()
        print('扫描耗时 {} 秒'.format(stop_time - start_time))
        print()
        return output

    '''
        controller enumerating ports by threads:
    '''
    def __XMas_ports_controller(self, ip, delay, output, message):
        """
        打开多个线程执行 TCP 端口扫描。
        """
        # 初始化 port_index 变量为 0。
        port_index = 0

        # 检查当前运行的线程数是否小于指定的线程限制，并且是否还有目标端口未被扫描。
        while threading.activeCount() < self.__thread_limit and port_index < len(self.portlist):
            # 创建一个新的线程来扫描下一个目标端口。
            thread = threading.Thread(target=self.__XMas_scan,
                                      args=(ip, self.portlist[port_index], delay, output, message))
            # 启动线程开始扫描。
            thread.start()
            # 将 port_index 变量增加 1 以扫描下一个目标端口。
            port_index = port_index + 1
            # 等待一段时间，以便其他线程有机会运行。
            time.sleep(0.01)

    def __Tcpscan_ports_controller(self, ip, delay, output, message):
        """
        打开多个线程执行 TCP 端口扫描。
        """
        # 初始化 port_index 变量为 0。
        port_index = 0

        # 检查当前运行的线程数是否小于指定的线程限制，并且是否还有目标端口未被扫描。
        while threading.activeCount() < self.__thread_limit and port_index < len(self.portlist):
            # 创建一个新的线程来扫描下一个目标端口。
            thread = threading.Thread(target=self.__TCP_scan,
                                      args=(ip, self.portlist[port_index], delay, output, message))
            # 启动线程开始扫描。
            thread.start()
            # 将 port_index 变量增加 1 以扫描下一个目标端口。
            port_index = port_index + 1
            # 等待一段时间，以便其他线程有机会运行。
            time.sleep(0.01)

    def __Finscan_ports_controller(self, ip, delay, output, message):
        port_index = 0

        while threading.activeCount() < self.__thread_limit and port_index < len(self.portlist):
            thread = threading.Thread(target=self.__FIN_scan,
                                      args=(ip, self.portlist[port_index], delay, output, message))
            thread.start()
            port_index = port_index + 1
            time.sleep(0.01)

    def __Synscan_ports_controller(self, ip, delay, output, message):
        port_index = 0

        while threading.activeCount() < self.__thread_limit and port_index < len(self.portlist):
            thread = threading.Thread(target=self.__SYN_scan,
                                      args=(ip, self.portlist[port_index], delay, output, message))
            thread.start()
            port_index = port_index + 1
            time.sleep(0.01)

    def __Udpscan_ports_controller(self, ip, delay, output, message):
        port_index = 0

        while threading.activeCount() < self.__thread_limit and port_index < len(self.portlist):
            thread = threading.Thread(target=self.__UDP_scan,
                                      args=(ip, self.portlist[port_index], delay, output, message))
            thread.start()
            port_index = port_index + 1
            time.sleep(0.01)

    def __Ackscan_ports_controller(self, ip, delay, output, message):
        port_index = 0

        while threading.activeCount() < self.__thread_limit and port_index < len(self.portlist):
            thread = threading.Thread(target=self.__ACK_scan,
                                      args=(ip, self.portlist[port_index], delay, output, message))
            thread.start()
            port_index = port_index + 1
            time.sleep(0.01)

    '''
        scan one port
    '''
    def __brute_check(self, ip: str, port_number: int, output: dict):
        # 未检查过
        if output.get(port_number)=='开放':
            return False

        # 检查端口是否未Brute.PORT_DIC中的
        if port_number not in Brute.PORT_DIC:
            return False

        with self.__print_lock:
            print(f'检测特殊{ip}:{port_number}端口, 正在启动爆破窗口')
        gui = BruteUI(ip, port_number, Brute.PORT_DIC[port_number])
        gui.create_ui_thread()

    def __XMas_scan(self, ip, port_number, delay, output, message):
        src_port = RandShort()  # 生成随机源端口
        xmas_packet = IP(dst=ip) / TCP(sport=src_port, dport=port_number, flags="FPU")

        response = sr1(xmas_packet, timeout=5, verbose=0)

        if response is None:
            with self.__print_lock:
                print(f"XMas: {ip}:{port_number} 可能是打开的（无响应）")
            self.__brute_check(ip, port_number, output)
            output[port_number] = '开放'
        elif response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            if tcp_layer.flags == 0x14:  # RST-ACK 标志位
                # print(f"XMas: {ip}:{port_number} 是关闭的")
                output[port_number] = '关闭'
            else:
                with self.__print_lock:
                    print(f"XMas: {ip}:{port_number} 可能是打开的")
                self.__brute_check(ip, port_number, output)
                output[port_number] = '开放'
        else:
            output[port_number] = '关闭'
        # elif response.haslayer(ICMP):
        #     icmp_layer = response.getlayer(ICMP)
        #     if icmp_layer.type == 3 and icmp_layer.code in (1, 2, 3, 9, 10, 13):
        #         print(f"XMas: {ip}:{port_number} 是被过滤的")

    def __TCP_scan(self, ip, port_number, delay, output, message):
        # 创建一个TCP socket对象，设置socket选项和超时时间
        TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        TCP_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        TCP_sock.settimeout(self.__delay)

        # 如果存在非空消息，则初始化一个UDP socket以发送扫描警报消息
        UDP_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        UDP_sock.sendto(self.__message, (ip, int(port_number)))

        try:
            # 连接目标IP地址和端口号
            result = TCP_sock.connect_ex((ip, int(port_number)))

            # 如果TCP握手成功，则端口为打开状态。否则为关闭状态。
            if result == 0:
                self.__brute_check(ip, port_number, output)
                self.__brute_check(ip, port_number, output)
                output[port_number] = '开放'
                with self.__print_lock:
                    print(f'TCP: {ip} 端口 {port_number} 开放')
            else:
                output[port_number] = '关闭'

            # 关闭TCP socket对象
            TCP_sock.close()

        except socket.error as e:
            # 执行TCP握手失败表示端口可能关闭。
            output[port_number] = '关闭'
            pass

    def __FIN_scan(self, ip, port_number, delay, output, message):
        p = IP(dst=ip) / TCP(dport=int(port_number), flags="F")
        ans = sr1(p, timeout=1, verbose=0)
        if sr1(p, timeout=1, verbose=0) == None:
            self.__brute_check(ip, port_number, output)
            output[port_number] = '开放'
            with self.__print_lock:
                print(f'FIN: {ip} 端口 {port_number} 开放')
        else:
            output[port_number] = '关闭'

    def __SYN_scan(self, ip, port_number, delay, output, message):
        sport = RandShort()
        pkt = IP(dst=ip) / TCP(sport=sport,dport=int(port_number), flags="S")
        ans =  sr1(pkt, timeout=1, verbose=0)
        if pkt != None:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 18:
                    self.__brute_check(ip, port_number, output)
                    output[port_number] = '开放'
                    with self.__print_lock:
                        print(f'SYN: {ip} 端口 {port_number} 开放')
                else:
                    output[port_number] = '关闭'

    def __UDP_scan(self, ip, port_number, delay, output, message):
        pkt = IP(dst=ip) / UDP(dport=int(port_number))
        res = sr1(pkt, timeout=0.1, verbose=0)
        if res == None:
            self.__brute_check(ip, port_number, output)
            output[port_number] = '开放'
            with self.__print_lock:
                print(f'UDP: {ip} 端口 {port_number} 开放')
        else:
            output[port_number] = '关闭'

    def __ACK_scan(self, ip, port_number, delay, output, message):
        sport = RandShort()
        pkt = IP(dst=ip) / TCP(sport=sport, dport=port_number, flags="A")
        res =  sr1(pkt, timeout=1, verbose=0)
        if pkt != None:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 4:
                    self.__brute_check(ip, port_number, output)
                    output[port_number] = '开放'
                    with self.__print_lock:
                        print(f'ACK: {ip} 端口 {port_number} 开放')
                else:
                    output[port_number] = '关闭'
