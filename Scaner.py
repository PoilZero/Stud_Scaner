from scan.port_scan import PortScanner
from scan.host_scan import HostScanner
from utils.scanner_parser import options
import warnings

def main():
    # scanner = PortScanner(options)
    Scanner = {'portscan':PortScanner, 'hostscan':HostScanner}[options['process_type']]
    Scanner(options)

if __name__ == "__main__":
    warnings.filterwarnings('ignore')
    main()
    input('按任意键结束进程')