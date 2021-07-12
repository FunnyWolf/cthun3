# -*- coding: utf-8 -*-
# @File  : http_jboss.py
# @Date  : 2019/12/20
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf

from vulscan.common import *


class CVE_2017_12149(object):
    def __init__(self, url):
        self.url = url
        self.headers = parse_headers()

        self.data = '{}'
        self.is_vul = False

    def check(self):
        payload = self.url + "/invoker/readonly"
        try:
            r = requests.post(payload, data=self.data, headers=self.headers)
            if r.status_code == 500:
                return True
            else:
                return False
        except Exception as e:
            return False


if __name__ == '__main__':
    s = CVE_2017_12149("http://192.168.8.110:8080")
    print(s.check())
