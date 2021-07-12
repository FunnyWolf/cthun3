# -*- coding: utf-8 -*-
# @File  : netbios.py
# @Date  : 2019/12/10
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf
from gevent import joinall
from impacket.nmb import NetBIOS

from lib.config import logger

TYPE_UNKNOWN = 0x01
TYPE_WORKSTATION = 0x00
TYPE_CLIENT = 0x03
TYPE_SERVER = 0x20
TYPE_DOMAIN_MASTER = 0x1B
TYPE_DOMAIN_CONTROLLER = 0x1C
TYPE_MASTER_BROWSER = 0x1D
TYPE_BROWSER = 0x1E
TYPE_NETDDE = 0x1F
TYPE_STATUS = 0x21


def netbios_interface(ipaddress_list, timeout, pool):
    tasks = []

    for ipaddress in ipaddress_list:
        task = pool.spawn(netbios_scan, ipaddress, timeout * 2)
        tasks.append(task)
        if len(tasks) >= 300:
            joinall(tasks)
            tasks = []
    joinall(tasks)


def netbios_scan(ipaddress, timeout):
    n = NetBIOS()
    result = {"ip": ipaddress, "domain": None, "name": None, "nets": [], "mac": None}
    try:
        entries = n.getnodestatus('*', ipaddress, timeout=timeout)
        result['mac'] = n.getmacaddress()

    except Exception as E:
        return
    for entrie in entries:
        if entrie["TYPE"] == TYPE_SERVER:
            result["name"] = entrie["NAME"].strip().decode('latin-1')
        elif entrie["TYPE"] == TYPE_WORKSTATION:
            result["domain"] = entrie["NAME"].strip().decode('latin-1')
        elif entrie["TYPE"] == TYPE_CLIENT:
            result["TYPE_CLIENT"] = entrie["NAME"].strip().decode('latin-1')
        elif entrie["TYPE"] == TYPE_DOMAIN_MASTER:
            result["TYPE_DOMAIN_MASTER"] = entrie["NAME"].strip().decode('latin-1')
        elif entrie["TYPE"] == TYPE_DOMAIN_CONTROLLER:
            result["TYPE_DOMAIN_CONTROLLER"] = entrie["NAME"].strip().decode('latin-1')
        elif entrie["TYPE"] == TYPE_MASTER_BROWSER:
            result["TYPE_MASTER_BROWSER"] = entrie["NAME"].strip().decode('latin-1')
        elif entrie["TYPE"] == TYPE_STATUS:
            result["TYPE_STATUS"] = entrie["NAME"].strip().decode('latin-1')

    try:
        if result.get("name") is not None:
            resp = n.name_query_request(result.get("name"), ipaddress, timeout=timeout)
            result["nets"].extend(resp.entries)

    except Exception as e:
        pass
    format_str = "{:<16}{:<20}{:<20}{:<20}{}".format(ipaddress,
                                                     result.get("domain"),
                                                     result.get("name"),
                                                     result.get("mac"),
                                                     result.get("nets"))
    logger.warning(format_str)
