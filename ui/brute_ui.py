from tkinter import *
from tkinter import filedialog
import threading
from brute.brute import Brute
from tkinter import *
from tkinter import filedialog
import threading
from brute.brute import Brute

class BruteUI:
    def __init__(self, ip, port_number, brute_type):
        self.ip = ip
        self.port_number = port_number
        self.brute_type = brute_type
        self.window = None

    def create_ui(self):
        # 创建窗口
        self.window = Tk()
        self.window.title(f"{self.ip}:{self.port_number}的{self.brute_type}爆破建议")

        # 定义选择文件函数
        def choose_file():
            file_path = filedialog.askopenfilename()
            var_dropdown.set(file_path)

        # 创建下拉栏
        var_dropdown = StringVar(self.window)
        var_dropdown.set("选择字典文件")
        dropdown = OptionMenu(self.window, var_dropdown, '选择字典文件')

        # 创建按钮
        brute_solver = Brute(self.window, self.brute_type, var_dropdown)
        button_blast = Button(self.window, text="爆破", command=brute_solver.solve) # 触发后才读取处理文件
        button_cancel = Button(self.window, text="取消", command=self.window.destroy)
        button_choose = Button(self.window, text="选择文件", command=choose_file)

        # 使用Grid布局来排列小部件
        dropdown.grid(row=0, column=0, padx=10, pady=10)
        button_choose.grid(row=0, column=1, padx=10, pady=10)
        button_blast.grid(row=1, column=0, padx=10, pady=10, sticky=N+S+E+W)
        button_cancel.grid(row=1, column=1, padx=10, pady=10, sticky=N+S+E+W)

        # 设置列权重，以便在窗口调整大小时可以适当拉伸下拉菜单和按钮
        self.window.columnconfigure(0, weight=1)
        self.window.columnconfigure(1, weight=1)

        # 运行窗口
        self.window.mainloop()

    def create_ui_thread(self):
        # 创建一个新线程并运行do_blast函数
        blast_thread = threading.Thread(target=self.create_ui)
        blast_thread.start()

if __name__ == "__main__":
    # 创建窗口
    gui = BruteUI('127.0.0.1', 2, 'ssh')
    gui.create_ui_thread()
    gui = BruteUI('127.0.0.1', 2, 'ftp')
    gui.create_ui_thread()
    gui = BruteUI('127.0.0.1', 2, 'mysql')
    gui.create_ui_thread()
    input()
