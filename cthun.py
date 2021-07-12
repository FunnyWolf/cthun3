# -*- coding: utf-8 -*-
# @File  : main.py
# @Date  : 2019/9/3
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf
import argparse
import datetime
import os
import sys
import time
from itertools import groupby

from ipaddr import summarize_address_range, IPv4Network, IPv4Address

from portscan.RE_DATA import TOP_1000_PORTS_WITH_ORDER


def group_numbers(lst):
    templist = []
    fun = lambda x: x[1] - x[0]
    for k, g in groupby(enumerate(lst), fun):
        l1 = [j for i, j in g]
        if len(l1) > 1:
            scop = str(min(l1)) + '-' + str(max(l1))
        else:
            scop = l1[0]
        templist.append(scop)
    return templist


def calc_ipaddresses(raw_input):
    if raw_input is None:
        return []
    format_lines = []
    raw_lines = raw_input.split(",")
    for line in raw_lines:
        # 是否是文件
        try:
            with open(line, "r") as f:
                filelines = f.readlines()
                for fileline in filelines:
                    format_lines.extend(fileline.strip().split(","))
        except Exception as _:
            format_lines.append(line)

    ipaddress_list = []
    for line in format_lines:
        if '-' in line:
            try:
                startip = line.split("-")[0]
                endip = line.split("-")[1]
                ipnetwork_list = []
                try:
                    if int(endip) > 0 and int(endip) <= 255:
                        ipnetwork_list = summarize_address_range(IPv4Address(startip),
                                                                 IPv4Address(int(IPv4Address(startip)) + int(endip)))
                except Exception as _:
                    ipnetwork_list = summarize_address_range(IPv4Address(startip), IPv4Address(endip))

                for ipnetwork in ipnetwork_list:
                    for ip in ipnetwork:
                        if ip.compressed not in ipaddress_list:
                            ipaddress_list.append(ip.compressed)
            except Exception as E:
                print(E)
        else:
            try:
                ipnetwork = IPv4Network(line)
                for ip in ipnetwork:
                    if ip.compressed not in ipaddress_list:
                        ipaddress_list.append(ip.compressed)
            except Exception as E:
                print(E)

    return ipaddress_list


def calc_ipaddress_port(raw_input):
    if raw_input is None:
        return []
    format_lines = []
    raw_lines = raw_input.split(",")
    for line in raw_lines:
        # 是否是文件
        try:
            with open(line, "r") as f:
                filelines = f.readlines()
                for fileline in filelines:
                    format_lines.extend(fileline.strip().split(","))
        except Exception as _:
            format_lines.append(line)

    ipaddress_port_list = []
    for oneline in format_lines:
        if ":" in oneline:
            try:
                line = oneline.split(":")[0]
                port = int(oneline.split(":")[1])
            except Exception as E:
                continue

            if '-' in line:
                try:
                    startip = line.split("-")[0]
                    endip = line.split("-")[1]
                    try:
                        if int(endip) > 0 and int(endip) <= 255:
                            ipnetwork_list = summarize_address_range(IPv4Address(startip),
                                                                     IPv4Address(
                                                                         int(IPv4Address(startip)) + int(endip)))
                        else:
                            ipnetwork_list = []
                    except Exception as _:
                        ipnetwork_list = summarize_address_range(IPv4Address(startip), IPv4Address(endip))

                    for ipnetwork in ipnetwork_list:
                        for ip in ipnetwork:
                            if "{}:{}".format(ip.compressed, port) not in ipaddress_port_list:
                                ipaddress_port_list.append("{}:{}".format(ip.compressed, port))
                except Exception as E:
                    print(E)
            else:
                try:
                    ipnetwork = IPv4Network(line)
                    for ip in ipnetwork:
                        if "{}:{}".format(ip.compressed, port) not in ipaddress_port_list:
                            ipaddress_port_list.append("{}:{}".format(ip.compressed, port))
                except Exception as E:
                    print(E)
        else:
            continue

    return ipaddress_port_list


def get_one_result(raw_line, proto):
    try:
        proto_default_port = {'ftp': 21, 'ssh': 22, 'rdp': 3389, 'smb': 445, 'mysql': 3306, 'mssql': 1433,
                              'redis': 6379, 'mongodb': 27017, 'memcached': 11211,
                              'postgresql': 5432, 'vnc': 5901, "http": 80, "ssl/http": 443, "https": 443}
        if len(raw_line.split(":")) < 2:
            # 没有填写端口,使用默认端口
            port = proto_default_port.get(proto)
        else:
            port = int(raw_line.split(":")[1])
        ip = raw_line.split(":")[0]
        return [{"ipaddress": ip, "port": port, "service": proto}]
    except Exception as E:
        print(E)
        return []


def write_finish_flag():
    logfilepath = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), finishlogfile)
    with open(logfilepath, 'w') as f:
        f.write(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Scanner for Intranet.")

    parser.add_argument('-ps-ip', '--portscan-ipaddress',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Portscan ipaddress.(e.g. 192.168.146.1-255,192.168.146.1/24,ip.txt)",
                        )

    parser.add_argument('-ps-p', '--portscan-ports',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Portscan ports.(e.g. 22,80,1-65535)",
                        )

    parser.add_argument('-ps-tp', '--portscan-topports',
                        metavar='N',
                        help='Most commonly used N ports(e.g. 100).',
                        default=0,
                        type=int)

    parser.add_argument('-ps-r', '--portscan-retry',
                        metavar='N',
                        help='Number of times to connect one port (e.g. 1).',
                        default=1,
                        type=int)

    parser.add_argument('-ns-ip', '--netbiosscan-ipaddress',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Netbiosscan ipaddress.(e.g. 192.168.146.1-255,192.168.146.1/24,ip.txt)",
                        )

    parser.add_argument('-hs-ipport', '--httpscan-ipaddress-ports',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Httpscan ip:port or set 'ps' to  use portscan result.(e.g. 192.168.146.1/24:8009,192.168.146.1-255:80,ipport.txt)",
                        )

    parser.add_argument('-hs-url', '--httpscan-url',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Httpscan check website has url(return 200).(e.g. /admin/login.jsp,/js/ijustcheck.js,/shell.php)",
                        )

    parser.add_argument('-bf', '--bruteforce',
                        default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="Run bruteforce with portscan result with all proto",
                        )

    parser.add_argument('-bf-smb', '--bruteforce-smb',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce smb ip:port or set 'ps' to  use portscan result.(e.g. 192.168.146.1/24:445,192.168.146.1-255:445,ipport.txt)",
                        )

    parser.add_argument('-bf-ssh', '--bruteforce-ssh',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce ssh ip:port or set 'ps' to  use portscan result.(e.g. 192.168.146.1/24:22,192.168.146.1-255:22,ipport.txt)",
                        )

    parser.add_argument('-bf-redis', '--bruteforce-redis',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce redis ip:port or set 'ps' to  use portscan result.(e.g. 192.168.146.1/24:6379,192.168.146.1-255:6379,ipport.txt)",
                        )

    parser.add_argument('-bf-ftp', '--bruteforce-ftp',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce ftp ip:port or set 'ps' to  use portscan result.(e.g. 192.168.146.1/24:6379,192.168.146.1-255:21,ipport.txt)",
                        )

    parser.add_argument('-bf-rdp', '--bruteforce-rdp',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce rdp ip:port or set 'ps' to  use portscan result.(e.g. 192.168.146.1/24:3389,192.168.146.1-255:3389,ipport.txt)",
                        )

    parser.add_argument('-bf-mysql', '--bruteforce-mysql',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce mysql ip:port or set 'ps' to  use portscan result.(e.g. 192.168.146.1/24:3306,192.168.146.1-255:3306,ipport.txt)",
                        )

    parser.add_argument('-bf-mongodb', '--bruteforce-mongodb',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce mongodb ip:port or set 'ps' to  use portscan result.(e.g. 192.168.146.1/24:27017,192.168.146.1-255:27017,ipport.txt)",
                        )

    parser.add_argument('-bf-memcached', '--bruteforce-memcached',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce memcached ip:port or set 'ps' to  use portscan result.(e.g. 192.168.146.1/24:11211,192.168.146.1-255:11211,ipport.txt)",
                        )

    parser.add_argument('-bf-vnc', '--bruteforce-vnc',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce vnc ip:port or set 'ps' to  use portscan result.(e.g. 192.168.146.1/24:5900,192.168.146.1-255:5900,ipport.txt)",
                        )

    parser.add_argument('-bf-u', '--bruteforce-users',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce usernames.(e.g. lab\\administrator,administrator,root,user.txt)",
                        )

    parser.add_argument('-bf-p', '--bruteforce-passwords',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce passwords.(e.g. 1234qwer!@#$,root,foobared,password.txt)",
                        )

    parser.add_argument('-bf-h', '--bruteforce-hashes',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce hashes.(e.g. hashes.txt)",
                        )

    parser.add_argument('-bf-sk', '--bruteforce-sshkeys',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce sshkeys.(e.g. id_rsa)",
                        )

    parser.add_argument('-bf-dd', '--bruteforce-defaultdict',
                        default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="Run bruteforce with built in dictionary",
                        )

    parser.add_argument('-vs', '--vulscan',
                        default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="Run vulnerability scanning",
                        )

    parser.add_argument('-vs-smb', '--vulscan-smb',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Bruteforce smb ip:port.(e.g. 192.168.146.1/24:445,192.168.146.1-255:445,ipport.txt)",
                        )
    parser.add_argument('-vs-http', '--vulscan-http',
                        default=None,
                        metavar='STR',
                        type=str,
                        help="Httpscan ip:port.(e.g. 192.168.146.1/24:8009,192.168.146.1-255:80,ipport.txt)",
                        )

    parser.add_argument('-ms', '--maxsocket',
                        metavar='N',
                        help='Maximum number of network connections(e.g. 300).',
                        default=100,
                        type=int)

    parser.add_argument('-st', '--sockettimeout',
                        metavar='N',
                        help='Socket Timeout(second)(e.g. 0.2)',
                        default=0.1,
                        type=float)

    parser.add_argument('-lh', '--loadhistory',
                        default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="Whether load historical data.(ipportservice.log)",
                        )

    parser.add_argument('-d', '--debug',
                        default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="Run in debug mode",
                        )

    args = parser.parse_args()

    from lib.config import logger, work_path, ipportservicelogfilename, finishlogfile

    # 获取时间戳
    logger.info("----------------- Progrem Start ---------------------")

    # 处理debug标签
    if args.debug is not False:
        fullname = "debug.log"
        sys.stderr = open(fullname, "w+")
    else:
        sys.stderr = None

    # 处理最大连接数
    max_socket_count = args.maxsocket
    if max_socket_count <= 100:
        max_socket_count = 100
    elif max_socket_count >= 1000:
        max_socket_count = 1000

    # 处理socket超时时间
    timeout = args.sockettimeout

    if timeout <= 0.1:
        timeout = 0.1
    elif timeout >= 1:
        timeout = 1

    # 公共变量

    portScan_result_list = []

    # 加载历史记录
    if args.loadhistory is not False:
        loadcount = 0
        # 读取文件中保存的ip地址,端口,服务
        filepath = os.path.join(work_path, ipportservicelogfilename)
        try:
            with open(filepath, "r") as f:
                file_lines = f.readlines()
                for line in file_lines:
                    ip = line.strip().split(",")[0]
                    port = line.strip().split(",")[1]
                    proto = line.strip().split(",")[2]
                    try:
                        one_record = {"ipaddress": ip, "port": port, "service": proto}
                        if one_record not in portScan_result_list:
                            loadcount += 1
                            portScan_result_list.append({"ipaddress": ip, "port": port, "service": proto})
                    except Exception as E:
                        pass
        except Exception as E:
            pass
        logger.info("Load {} ip:port:service from ipportservice.log".format(loadcount))

    from gevent.pool import Pool

    pool = Pool(max_socket_count)

    # 检查是否需要进行portscan
    # 检查是否需要进行portscan
    portscan = False
    portscan_ipaddress = args.portscan_ipaddress
    portscan_ports = args.portscan_ports
    portscan_topports = args.portscan_topports
    portscan_retry = args.portscan_retry
    ip_list = []
    if portscan_ipaddress is None:
        portscan = False
    else:
        ip_list = calc_ipaddresses(portscan_ipaddress)
        if len(ip_list) <= 0:
            logger.warning("Can not get portscan ipaddress from -ps-ip")
            portscan = False
        else:
            portscan = True

    port_list = []
    showports = ""
    if portscan:
        if portscan_ports is not None:
            ports_lines = portscan_ports.split(",")
            for one in ports_lines:
                try:
                    if len(one.split("-")) == 2:
                        start_port = int(one.split("-")[0])
                        end_port = int(one.split("-")[1])
                        for i in range(start_port, end_port + 1):
                            if i not in port_list and (0 < i <= 65535):
                                port_list.append(i)
                    else:
                        i = int(one)
                        if i not in port_list and (0 < i <= 65535):
                            port_list.append(i)
                except Exception as E:
                    pass
        else:
            if portscan_topports == 0:
                logger.info("Do not input -ps-port and -ps-tp, just set portscan_topports to 100")
                portscan_topports = 100

        if portscan_topports <= 0:
            portscan_topports = 0
        elif portscan_topports >= 1000:
            portscan_topports = 1000

        top_port_list = TOP_1000_PORTS_WITH_ORDER[0:portscan_topports]
        for i in top_port_list:
            if i not in port_list:
                port_list.append(i)

        if len(port_list) <= 0:
            logger.warning("Can not get portscan ports from -ip-port and -ip-tp.")
            portscan = False
        else:
            showports = group_numbers(port_list)

    if portscan:
        if portscan_retry <= 1:
            portscan_retry = 1
        elif portscan_retry >= 3:
            portscan_retry = 3

        logger.info("----------------- PortScan Start --------------------")
        logger.info(
            "IP list: {}\tIP count: {}\tSocketTimeout: {}\tMaxsocket: {}\tPorts: {}".format(portscan_ipaddress,
                                                                                            len(ip_list), timeout,
                                                                                            max_socket_count,
                                                                                            showports))
        t1 = time.time()

        from portscan.portScan import GeventScanner

        geventScanner = GeventScanner(max_socket_count=max_socket_count, timeout=timeout, retry=portscan_retry)
        portScan_result_list = geventScanner.aysnc_main(ip_list, port_list, pool)
        t2 = time.time()
        logger.info("PortScan finish,time use : {}s".format(format(t2 - t1, '.2f')))
        logger.info("----------------- PortScan Finish --------------------")

    # 检查是否需要进行netbiosscan
    # 检查是否需要进行netbiosscan
    netbiosscan = False
    netbiosscan_ipaddress = args.netbiosscan_ipaddress
    ip_list = []
    if netbiosscan_ipaddress is None:
        netbiosscan = False
    else:
        ip_list = calc_ipaddresses(netbiosscan_ipaddress)
        if len(ip_list) <= 0:
            logger.warning("Can not get netbiosscan ipaddress from -ns-ip")
            netbiosscan = False
        else:
            netbiosscan = True

    if netbiosscan:
        logger.info("----------------- Netbios Scan Start ----------------------")
        logger.info(
            "IP list: {}\tIP count: {}\tSocketTimeout: {}\tMaxsocket: {}".format(netbiosscan_ipaddress,
                                                                                 len(ip_list),
                                                                                 timeout,
                                                                                 max_socket_count,
                                                                                 ))
        t3 = time.time()
        from gevent.monkey import patch_all

        patch_all()
        from netbios.netbios import netbios_interface

        netbios_interface(ip_list, timeout, pool)
        t4 = time.time()
        logger.info("Netbios Scan finish,time use : {} s".format(format(t4 - t3, '.2f')))
        logger.info("----------------- Netbios Scan Finish ---------------------")

    # 检查是否需要进行httpscan
    # 检查是否需要进行httpscan
    httpscan = False
    httpscan_ipaddress_ports = args.httpscan_ipaddress_ports
    httpscan_url = args.httpscan_url

    ip_port_list = calc_ipaddress_port(httpscan_ipaddress_ports)

    if ip_port_list:
        for line in ip_port_list:
            manly_input_result = get_one_result(line.strip(), "http")
            portScan_result_list.extend(manly_input_result)
            manly_input_result = get_one_result(line.strip(), "https")
            portScan_result_list.extend(manly_input_result)
        httpscan = True
    else:
        if httpscan_ipaddress_ports is not None:
            if portScan_result_list:
                httpscan = True
            else:
                logger.warning("No result from portscan,httpscan not run")
                httpscan = False

    if httpscan:
        if httpscan_url is None:
            flagurl = []
        else:
            flagurl = httpscan_url.split(",")

        logger.info("----------------- HttpCheck Start ----------------------")
        t3 = time.time()
        from gevent.monkey import patch_all

        patch_all()
        from httpcheck.httpCheck import http_interface

        http_interface(portScan_result_list, timeout, pool, flagurl)
        t4 = time.time()
        logger.info("HttpCheck finish,time use : {}s".format(format(t4 - t3, '.2f')))
        logger.info("----------------- HttpCheck Finish ---------------------")

    # 检查是否需要进行bruteforce
    # 检查是否需要进行bruteforce
    bruteforce = args.bruteforce

    bruteforce_smb = args.bruteforce_smb
    bruteforce_ssh = args.bruteforce_ssh
    bruteforce_redis = args.bruteforce_redis
    bruteforce_ftp = args.bruteforce_ftp
    bruteforce_rdp = args.bruteforce_rdp
    bruteforce_mysql = args.bruteforce_mysql
    bruteforce_mongodb = args.bruteforce_mongodb
    bruteforce_memcached = args.bruteforce_memcached
    bruteforce_vnc = args.bruteforce_vnc

    bruteforce_defaultdict = args.bruteforce_defaultdict
    bruteforce_users = args.bruteforce_users
    bruteforce_passwords = args.bruteforce_passwords
    bruteforce_hashes = args.bruteforce_hashes
    bruteforce_sshkeys = args.bruteforce_sshkeys

    proto_list = []

    if bruteforce_smb is not None:
        proto_list.append("smb")
        ip_port_list_smb = calc_ipaddress_port(bruteforce_smb)
        for line in ip_port_list_smb:
            portScan_result_list.extend(get_one_result(line.strip(), "smb"))

    if bruteforce_ssh is not None:
        proto_list.append("ssh")
        ip_port_list_ssh = calc_ipaddress_port(bruteforce_ssh)
        for line in ip_port_list_ssh:
            portScan_result_list.extend(get_one_result(line.strip(), "ssh"))

    if bruteforce_redis is not None:
        proto_list.append("redis")
        ip_port_list_redis = calc_ipaddress_port(bruteforce_redis)
        for line in ip_port_list_redis:
            portScan_result_list.extend(get_one_result(line.strip(), "redis"))

    if bruteforce_ftp is not None:
        proto_list.append("ftp")
        ip_port_list_ftp = calc_ipaddress_port(bruteforce_ftp)
        for line in ip_port_list_ftp:
            portScan_result_list.extend(get_one_result(line.strip(), "ftp"))
    if bruteforce_rdp is not None:
        proto_list.append("ftp")
        ip_port_list_rdp = calc_ipaddress_port(bruteforce_rdp)
        for line in ip_port_list_rdp:
            portScan_result_list.extend(get_one_result(line.strip(), "rdp"))

    if bruteforce_mysql is not None:
        proto_list.append("mysql")
        ip_port_list_mysql = calc_ipaddress_port(bruteforce_mysql)
        for line in ip_port_list_mysql:
            portScan_result_list.extend(get_one_result(line.strip(), "mysql"))

    if bruteforce_mongodb is not None:
        proto_list.append("mongodb")
        ip_port_list_mongodb = calc_ipaddress_port(bruteforce_mongodb)
        for line in ip_port_list_mongodb:
            portScan_result_list.extend(get_one_result(line.strip(), "mongodb"))

    if bruteforce_memcached is not None:
        proto_list.append("memcached")
        ip_port_list_memcached = calc_ipaddress_port(bruteforce_memcached)
        for line in ip_port_list_memcached:
            portScan_result_list.extend(get_one_result(line.strip(), "memcached"))

    if bruteforce_vnc is not None:
        proto_list.append("vnc")
        ip_port_list_vnc = calc_ipaddress_port(bruteforce_vnc)
        for line in ip_port_list_vnc:
            portScan_result_list.extend(get_one_result(line.strip(), "vnc"))

    if proto_list:
        if portScan_result_list:
            bruteforce = True
        else:
            logger.warning("No result from portscan and -bf-*,bruteforce not run")
            bruteforce = False
    else:
        if bruteforce is not False:
            if portScan_result_list:
                proto_list = ["smb", "ssh", "redis", "ftp", "rdp", "mysql", "mongodb", "memcached", "vnc"]
                logger.info("Run bruteforce on {}".format(proto_list))
                bruteforce = True
            else:
                logger.warning("No result from portscan,bruteforce not run")
                bruteforce = False
    users = []
    passwords = []
    hashes = []
    sshkeys = []
    if bruteforce:
        if bruteforce_users is not None:
            raw_lines = bruteforce_users.split(",")
            for line in raw_lines:
                try:
                    with open(line, "r") as f:
                        for fileline in f.readlines():
                            users.append(fileline.strip())
                except Exception as _:
                    users.append(line)

        if bruteforce_passwords is not None:
            raw_lines = bruteforce_passwords.split(",")
            for line in raw_lines:
                try:
                    with open(line, "r") as f:
                        for fileline in f.readlines():
                            passwords.append(fileline.strip())
                except Exception as _:
                    passwords.append(line)

        if bruteforce_hashes is not None:
            raw_lines = bruteforce_hashes.split(",")
            for line in raw_lines:
                # 是否是文件
                try:
                    with open(line, "r") as f:
                        for fileline in f.readlines():
                            hashes.append(fileline.strip())
                except Exception as _:
                    pass

        if bruteforce_sshkeys is not None:
            raw_lines = bruteforce_sshkeys.split(",")
            for line in raw_lines:
                # 是否是文件
                sshkeys.append(os.path.join(work_path, line))

        if bruteforce_defaultdict is not False:
            bruteforce_defaultdict = True

        if (users and passwords) or hashes or sshkeys:
            bruteforce = True
        else:
            if bruteforce_defaultdict:
                bruteforce = True
            else:
                logger.warning("No user and password dict was input,bruteforce not run")
                bruteforce = False

    if bruteforce:
        t2 = time.time()
        logger.info("----------------- BruteForce Start -------------------")
        logger.info("Protocols: {}\tDefaultdict: {}".format(proto_list, bruteforce_defaultdict))
        from gevent.monkey import patch_all

        patch_all()
        from bruteforce.bruteForce import bruteforce_interface

        bruteforce_interface(
            portScan_result_list=portScan_result_list,
            timeout=timeout,
            proto_list=proto_list,
            pool=pool,
            default_dict=bruteforce_defaultdict,
            users=users,
            passwords=passwords,
            hashes=hashes,
            ssh_keys=sshkeys,
        )
        t3 = time.time()
        logger.info("BruteForce finish,time use : {} s".format(format(t3 - t2, '.2f')))
        logger.info("----------------- BruteForce Finish --------------------")

    # 检查是否需要进行vulscan
    vulscan = args.vulscan
    vulscan_smb = args.vulscan_smb
    vulscan_http = args.vulscan_http

    proto_list = []

    if vulscan_smb is not None:
        proto_list.append("smb")
        ip_port_list_smb = calc_ipaddress_port(vulscan_smb)
        for line in ip_port_list_smb:
            portScan_result_list.extend(get_one_result(line.strip(), "smb"))

    if vulscan_http is not None:
        proto_list.append("http")
        proto_list.append("https")
        ip_port_list_http = calc_ipaddress_port(vulscan_http)
        for line in ip_port_list_http:
            portScan_result_list.extend(get_one_result(line.strip(), "http"))
            portScan_result_list.extend(get_one_result(line.strip(), "https"))

    if proto_list:
        if portScan_result_list:
            vulscan = True
        else:
            logger.warning("No result from portscan and -vs-smb -vs-http,vulscan not run")
            vulscan = False
    else:
        if vulscan is not False:
            if portScan_result_list:
                proto_list = ["smb", "http", "https"]
                logger.info("Run vulscan on {}".format(proto_list))
                vulscan = True
            else:
                logger.warning("No result from portscan,vulscan not run")
                vulscan = False

    if vulscan:
        logger.info("----------------- VulScan Start ---------------------")
        t3 = time.time()
        from gevent.monkey import patch_all

        patch_all()
        from vulscan.vulScan import vulscan_interface

        vulscan_interface(portScan_result_list=portScan_result_list, timeout=timeout, pool=pool)
        t4 = time.time()
        logger.info("Vulscan Scan finish,time use : {}s".format(format(t4 - t3, '.2f')))
        logger.info("----------------- VulScan Finish --------------------")

    logger.info("----------------- Progrem Finish -----------------------\n\n")

    # 写入结束标志
    try:
        write_finish_flag()
    except Exception as e:
        print(e)
