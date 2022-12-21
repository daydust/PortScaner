import socket
import os
import sys
from IPy import IP


def retBanner(ip, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        key = s.connect_ex((ip, port))
        if key == 0:
            print(f"\n成功链接到{ip}:{port}")
        else:
            print(f"\n无法链接到{ip}:{port}")
        banners = s.recv(1024)
        banners = banners.decode("UTF-8")
        return str(banners)
    except Exception as e:
        print(f"[-]{ip}:{port} Error = " + str(e)+"\n")
        return


def checkVulns(banner, filename):
    f = open(filename, 'r')
    for line in f.readlines():
        if line.strip('\n') in banner:
            print('[+] Server is vulnerable: ' + banner.strip('\n'))


def main():
    if len(sys.argv) == 2:
        filename = "vuln_banners.txt"
        if not os.path.isfile(filename):
            print('[-] ' + filename + ' does not exist.')
            exit(0)
        if not os.access(filename, os.R_OK):
            print('[-] ' + filename + ' access denied.')
            exit(0)
        else:
            print('[-] Usage: ' + str(sys.argv[0]) + ' <vuln filename>')
        portList = [21, 22, 80, 8080, 50, 53, 21, 23, 25, 80, 113, 137, 139, 555, 666, 1001, 1025, 1026, 1028, 1243,
                    2000, 500, 6667, 6670, 6711, 6776, 6969, 7000, 8080, 25, 135, 137, 139, 389, 445, 1024, 1025,
                    1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041,
                    1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 3306]
        ips = IP(sys.argv[1])
        for ip in ips:
            ip = str(ip)
            for port in portList:
                banner = retBanner(ip, port)
                if banner:
                    print('[+] ' + ip + ': ' + banner+"\n")
                    checkVulns(banner, filename)


if __name__ == '__main__':
    main()
