# -*- coding: utf-8 -*-
# @File  : vulscan.py
# @Date  : 2019/12/11
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf

import gevent

from lib.config import logger
from vulscan.http_confluence import *
from vulscan.http_jboss import *
from vulscan.http_struts2 import *
from vulscan.http_tomcat import *
from vulscan.http_weblogic import CVE_2017_10271, CVE_2018_2894, CVE_2019_2729
from vulscan.smb import ms17010scan


def http_scan(url):
    # confluence
    try:
        s = CVE_2019_3396(url)
        if s.check():
            format_str = "{:<25} VULNERABLE to CVE_2019_3396".format(url)
            logger.warning(format_str)
    except Exception as E:
        pass

    # jboss
    try:
        s = CVE_2017_12149(url)
        if s.check():
            format_str = "{:<25} VULNERABLE to CVE_2017_12149".format(url)
            logger.warning(format_str)

    except Exception as E:
        pass

    # struts2
    try:
        s = S2_015(url)
        if s.check():
            format_str = "{:<25} VULNERABLE to S2_015".format(url)
            logger.warning(format_str)
    except Exception as E:
        pass

    try:
        s = S2_016(url)
        if s.check():
            format_str = "{:<25} VULNERABLE to S2_016".format(url)
            logger.warning(format_str)
            format_str = "{:<25} Webpath: {}".format(url, s.get_path())
            logger.warning(format_str)
    except Exception as E:
        pass

    try:
        s = S2_045(url)
        if s.check():
            format_str = "{:<25} VULNERABLE to S2_045".format(url)
            logger.warning(format_str)
            format_str = "{:<25} Webpath: {}".format(url, s.get_path())
            logger.warning(format_str)
    except Exception as E:
        pass

    # tomcat
    try:
        s = CVE_2017_12615(url)
        if s.check():
            format_str = "{:<25} VULNERABLE to CVE_2017_12615".format(url)
            logger.warning(format_str)
            format_str = "{:<25} Webshell: {}".format(url, s.confirm_info())
            logger.warning(format_str)
    except Exception as E:
        pass

    try:
        s = WeakPassword(url)
        if s.check():
            format_str = "{:<25} VULNERABLE to WeakPassword".format(url)
            logger.warning(format_str)
    except Exception as E:
        pass

    # weblogic
    try:
        s = CVE_2017_10271(url)
        if s.check():
            format_str = "{:<25} VULNERABLE to CVE_2017_10271".format(url)
            logger.warning(format_str)
    except Exception as E:
        pass

    try:
        s = CVE_2018_2894(url)
        if s.check():
            format_str = "{:<25} VULNERABLE to CVE_2018_2894".format(url)
            logger.warning(format_str)
    except Exception as E:
        pass
    try:
        s = CVE_2019_2729(url)
        if s.check():
            format_str = "{:<25} VULNERABLE to CVE_2019_2729".format(url)
            logger.warning(format_str)

    except Exception as E:
        pass


def vulscan_interface(portScan_result_list, timeout, pool):
    pool = pool
    tasks = []
    for one_portscan_result in portScan_result_list:
        service = one_portscan_result.get("service").lower()
        ipaddress = one_portscan_result.get("ipaddress")
        port = one_portscan_result.get("port")

        if ("microsoft-ds" in service or "smb" in service):
            task = pool.spawn(ms17010scan, ipaddress, port)
            tasks.append(task)
            continue
        if "ssl/http" in service or "https" == service:
            url = "https://{}:{}".format(ipaddress, port)
            task = pool.spawn(http_scan, url)
            tasks.append(task)
            continue
        if "http" in service:
            url = "http://{}:{}".format(ipaddress, port)
            task = pool.spawn(http_scan, url)
            tasks.append(task)
            continue

    gevent.joinall(tasks)
