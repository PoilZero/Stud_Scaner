import socket
import ipaddress
import unittest

def resolve_address(address):
    ip_list = []
    # 判断是否是域名
    try:
        ipaddress.ip_network(address)
        is_domain = False
    except ValueError:
        is_domain = True

    if is_domain:
        print("解析域名:", address)
        try:
            addr_info_list = socket.getaddrinfo(address, None, family=socket.AF_UNSPEC)
            for addr_info in addr_info_list:
                ip = addr_info[4][0]  # 提取IP地址
                if ip not in ip_list:
                    ip_list.append(ip)
        except socket.gaierror:
            print("无法解析的域名")
            return []
    else:
        if '/' in address:
            print("解析网段:", address)
            # 如果是网段，遍历所有IP
            network = ipaddress.ip_network(address, strict=False)
            for ip in network.hosts():
                ip_list.append(str(ip))
        else:
            print("解析单个IP:", address)
            # 如果是单个IP，直接添加到列表
            ip_list.append(address)
    # print("结果:", ip_list)
    return ip_list

def resolve_address_file(file_path):
    ip_list = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                ips = resolve_address(line)
                ip_list.extend(ips)
    return ip_list

class TestResolveAddress(unittest.TestCase):
    def test_domain(self):
        address = "example.com"
        expected_result = ["93.184.216.34"]
        ip_list = resolve_address(address)
        self.assertEqual(set(ip_list), set(expected_result), "域名解析错误")

    def test_ipv4(self):
        address = "8.8.8.8"
        expected_result = ["8.8.8.8"]
        ip_list = resolve_address(address)
        self.assertEqual(ip_list, expected_result, "IPv4单个IP解析错误")

    def test_ipv6(self):
        address = "2001:4860:4860::8888"
        expected_result = ["2001:4860:4860::8888"]
        ip_list = resolve_address(address)
        self.assertEqual(ip_list, expected_result, "IPv6单个IP解析错误")

    def test_ipv4_subnet(self):
        address = "192.168.1.0/24"
        expected_result = [f"192.168.1.{i}" for i in range(1, 255)]
        ip_list = resolve_address(address)
        self.assertEqual(set(ip_list), set(expected_result), "IPv4网段解析错误")

    def test_ipv6_subnet(self):
        address = "2001:db8::/120"
        expected_result = [f"2001:db8::{format(i, 'x')}" for i in range(1, 256)]
        ip_list = resolve_address(address)
        self.assertEqual(set(ip_list), set(expected_result), "IPv6网段解析错误")

    def test_unresolvable_domain(self):
        address = "unresolvable.example"
        ip_list = resolve_address(address)
        self.assertEqual(ip_list, [], "无法解析的域名应返回空列表")


if __name__ == "__main__":
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
