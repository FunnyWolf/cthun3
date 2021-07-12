# -*- coding: utf-8 -*-
# @File  : common.py
# @Date  : 2019/12/20
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf 
import copy

import requests
from requests.exceptions import ChunkedEncodingError, ConnectionError, ConnectTimeout

default_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36'
}

# 全局代理
proxies = None
# 超时时间
_tiemout = 3


def get(url, headers=None, encoding='UTF-8'):
    """GET请求发送包装"""
    try:
        html = requests.get(url, headers=headers, proxies=proxies, timeout=_tiemout)
        html = html.content.decode(encoding)
        return html.replace('\x00', '').strip()
    except ChunkedEncodingError as e:
        html = get_stream(url, headers, encoding)
        return html
    except Exception as e:
        return 'ERROR:' + str(e)


def get_stream(url, headers=None, encoding='UTF-8'):
    """分块接受数据"""
    try:
        lines = requests.get(url, headers=headers, timeout=_tiemout, stream=True, proxies=proxies)
        html = list()
        for line in lines.iter_lines():
            if b'\x00' in line:
                break
            line = line.decode(encoding)
            html.append(line.strip())
        return '\r\n'.join(html).strip()
    except ChunkedEncodingError as e:
        return '\r\n'.join(html).strip()
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)


def post(url, data=None, headers=None, encoding='UTF-8', files=None):
    """POST请求发送包装"""
    try:
        html = requests.post(url, data=data, headers=headers, proxies=proxies, timeout=_tiemout, files=files)
        html = html.content.decode(encoding)
        return html.replace('\x00', '').strip()
    except ChunkedEncodingError as e:
        html = post_stream(url, data, headers, encoding, files)
        return html
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)


def post_stream(url, data=None, headers=None, encoding='UTF-8', files=None):
    """分块接受数据"""
    try:
        lines = requests.post(url, data=data, headers=headers, timeout=_tiemout, stream=True, proxies=proxies,
                              files=None)
        html = list()
        for line in lines.iter_lines():
            line = line.decode(encoding)
            html.append(line.strip())
        return '\r\n'.join(html).strip()
    except ChunkedEncodingError as e:
        return '\r\n'.join(html).strip()
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)


def parse_headers(headers=None):
    """将headers字符串解析为字典"""
    if not headers:
        return default_headers
    new_headers = copy.deepcopy(default_headers)
    headers = headers.split('&')
    for header in headers:
        header = header.split(':')
        new_headers[header[0].strip()] = header[1].strip()
    return new_headers
