# -*- coding: utf-8 -*-
# @File  : config.py
# @Date  : 2019/8/28
# @Desc  :
# @license : Copyright(C), funnywolf
# @Author: funnywolf
# @Contact : github.com/FunnyWolf
import datetime
import logging.config
import os
import sys

start_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H%M%S')
finishlogfile = "{} finish.log".format(start_timestamp)
work_path = os.path.dirname(os.path.realpath(sys.argv[0]))
logfilename = "{} running.log".format(start_timestamp)
logfilepath = os.path.join(work_path, logfilename)
ipportservicelogfilename = "ipportservice.log"
ipportservicelogfilepath = os.path.join(work_path, ipportservicelogfilename)

logconfig = {
    'version': 1,
    'formatters': {
        'simple': {
            'format': '%(asctime)s - %(levelname)s - %(lineno)s - %(message)s',
        },
        'raw': {
            'format': '%(message)s',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'DEBUG',
            'formatter': 'simple'
        },
        'release': {
            'class': 'logging.FileHandler',
            'filename': logfilepath,
            'level': 'INFO',
            'formatter': 'raw'
        },
        'ipportservice': {
            'class': 'logging.FileHandler',
            'filename': ipportservicelogfilepath,
            'level': 'INFO',
            'formatter': 'raw'
        },
    },
    'loggers': {
        'ReleaseLogger': {
            'handlers': ['console', 'release'],
            'level': "INFO",
        },
        'IpportserviceLogger': {
            'handlers': ['ipportservice'],
            'level': "INFO",
        },
    }
}

logging.config.dictConfig(logconfig)

logging.raiseExceptions = False
logger = logging.getLogger("ReleaseLogger")
ipportservicelogger = logging.getLogger("IpportserviceLogger")


def log_success(service, ipaddress, port, user_passwd_pair):
    if user_passwd_pair is None:
        format_str = "{:<16}{:<16}{:<7} unauthorized access ".format(service, ipaddress, port)
    else:
        format_str = "{:<16}{:<16}{:<7}{:<30}{}".format(service, ipaddress, port, user_passwd_pair[0],
                                                        user_passwd_pair[1])
    logger.warning(format_str)
