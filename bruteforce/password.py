# -*- coding: utf-8 -*-
# @File  : password.py
# @Date  : 2019/9/3
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf

from lib.config import logger


# 处理用户输入的用户名/密码


class Password_total(object):
    def __init__(self):

        self.password_dict = {
            "FTP": {
                "user": ["anonymous", "administrator", "ftp", "test", "admin", "web"],
                "password": ["", "{user}", "{user}123", "{user}1234", "{user}123456", "{user}12345", "{user}@123",
                             "{user}@123456", "{user}@12345", "{user}#123", "{user}#123456", "{user}#12345",
                             "{user}_123", "{user}_123456", "{user}_12345", "{user}123!@#", "{user}!@#$", "{user}!@#",
                             "{user}~!@", "{user}!@#123", "qweasdzxc", "{user}2017", "{user}2016", "{user}2015",
                             "{user}@2017", "{user}@2016", "{user}@2015", "Passw0rd", "admin123", "admin888",
                             "administrator", "administrator123", "ftp", "ftppass", "123456", "password", "12345",
                             "1234", "root", "123", "qwerty", "test", "1q2w3e4r", "1qaz2wsx", "qazwsx", "123qwe",
                             "123qaz", "0000", "oracle", "1234567", "123456qwerty", "password123", "12345678", "1q2w3e",
                             "abc123", "okmnji", "test123", "123456789", "q1w2e3r4", "user", "mysql", "web"],
            },
            "MongoDB": {
                "user": ["admin", "test", "system", "web"],
                "password": ["", "admin", "mongodb", "{user}", "{user}123", "{user}1234",
                             "{user}123456", "{user}12345", "{user}@123", "{user}@123456", "{user}@12345",
                             "{user}#123", "{user}#123456", "{user}#12345", "{user}_123", "{user}_123456",
                             "{user}_12345", "{user}123!@#", "{user}!@#$", "{user}!@#", "{user}~!@",
                             "{user}!@#123", "Passw0rd", "qweasdzxc", "{user}2017", "{user}2016", "{user}2015",
                             "{user}@2017", "{user}@2016", "{user}@2015", "admin123", "admin888", "administrator",
                             "administrator123", "mongodb123", "mongodbpass", "123456", "password", "12345", "1234",
                             "root", "123", "qwerty", "test", "1q2w3e4r", "1qaz2wsx", "qazwsx", "123qwe", "123qaz",
                             "0000", "oracle", "1234567", "123456qwerty", "password123", "12345678", "1q2w3e",
                             "abc123", "okmnji", "test123", "123456789", "q1w2e3r4", "user", "web", ""],
            },
            "MSSQL": {
                "user": ["sa"],
                "password": ["admin", "{user}", "{user}123", "{user}1234", "{user}123456", "{user}12345",
                             "{user}@123", "{user}@123456", "{user}@12345", "{user}#123", "{user}#123456",
                             "{user}#12345", "{user}_123", "{user}_123456", "{user}_12345", "{user}123!@#",
                             "{user}!@#$", "{user}!@#", "{user}~!@", "{user}!@#123", "qweasdzxc", "{user}2017",
                             "{user}2016", "{user}2015", "{user}@2017", "{user}@2016", "{user}@2015", "Passw0rd",
                             "qweasdzxc", "admin123", "admin888", "administrator", "administrator123", "sa123",
                             "ftp", "ftppass", "123456", "password", "12345", "1234", "sa", "123", "qwerty",
                             "test", "1q2w3e4r", "1qaz2wsx", "qazwsx", "123qwe", "123qaz", "0000", "oracle",
                             "1234567", "123456qwerty", "password123", "12345678", "1q2w3e", "abc123", "okmnji",
                             "test123", "123456789", "q1w2e3r4", "sqlpass", "sql123", "sqlserver", "web"],
            },
            "MYSQL": {
                "user": ["root"],
                "password": ["", "{user}", "{user}123", "{user}1234", "{user}123456", "{user}12345",
                             "{user}@123", "{user}@123456", "{user}@12345", "{user}#123", "{user}#123456",
                             "{user}#12345", "{user}_123", "{user}_123456", "{user}_12345", "{user}123!@#",
                             "{user}!@#$", "{user}!@#", "{user}~!@", "{user}!@#123", "qweasdzxc", "{user}2017",
                             "{user}2016", "{user}2015", "{user}@2017", "{user}@2016", "{user}@2015", "qweasdzxc",
                             "Passw0rd", "admin123", "admin888", "qwerty", "test", "1q2w3e4r", "1qaz2wsx", "qazwsx",
                             "123qwe", "123qaz", "123456qwerty", "password123", "1q2w3e", "okmnji", "test123",
                             "test12345", "test123456", "q1w2e3r4", "mysql", "web", "%username%", "%null%", "123",
                             "1234", "12345", "123456", "admin", "pass", "password", "!null!", "!user!", "1234567",
                             "7654321", "abc123", "111111", "123321", "123123", "12345678", "123456789", "000000",
                             "888888", "654321", "987654321", "147258369", "123asd", "qwer123", "P@ssw0rd",
                             "root3306", "Q1W2E3b3"],
            },
            "Memcached": {
                "user": ["admin", "test", "root", "web"],
                "password": ["", "Passw0rd", "admin", "{user}", "{user}123", "{user}1234", "{user}123456",
                             "{user}12345", "{user}@123", "{user}@123456", "{user}@12345", "{user}#123",
                             "{user}#123456", "{user}#12345", "{user}_123", "{user}_123456", "{user}_12345",
                             "{user}123!@#", "{user}!@#$", "{user}!@#", "{user}~!@", "{user}!@#123",
                             "qweasdzxc", "{user}2017", "{user}2016", "{user}2015", "{user}@2017", "{user}@2016",
                             "{user}@2015", "admin123", "admin888", "administrator", "administrator123",
                             "root123", "123456", "password", "12345", "1234", "root", "123", "qwerty", "test",
                             "1q2w3e4r", "1qaz2wsx", "qazwsx", "123qwe", "123qaz", "0000", "oracle", "1234567",
                             "123456qwerty", "password123", "12345678", "1q2w3e", "abc123", "okmnji", "test123",
                             "123456789", "q1w2e3r4", "user", "web", ""],
            },
            "PostgreSQL": {
                "user": ["postgres", "test", "admin", "web"],
                "password": ["admin", "Passw0rd", "postgres", "{user}", "{user}123", "{user}1234",
                             "{user}123456", "{user}12345", "{user}@123", "{user}@123456", "{user}@12345",
                             "{user}#123", "{user}#123456", "{user}#12345", "{user}_123", "{user}_123456",
                             "{user}_12345", "{user}123!@#", "{user}!@#$", "{user}!@#", "{user}~!@",
                             "{user}!@#123", "qweasdzxc", "{user}2017", "{user}2016", "{user}2015",
                             "{user}@2017", "{user}@2016", "{user}@2015", "admin123", "admin888",
                             "administrator", "administrator123", "root123", "ftp", "ftppass", "123456",
                             "password", "12345", "1234", "root", "123", "qwerty", "test", "1q2w3e4r",
                             "1qaz2wsx", "qazwsx", "123qwe", "123qaz", "0000", "oracle", "1234567",
                             "123456qwerty", "password123", "12345678", "1q2w3e", "abc123", "okmnji", "test123",
                             "123456789", "q1w2e3r4", "user", "web"],
            },
            "RDP": {
                "user": ["administrator", "admin", "test", "user", "manager", "webadmin", "guest", "db2admin"],
                "password": ["{user}", "{user}123", "{user}1234", "{user}123456", "{user}12345", "{user}@123",
                             "{user}@123456", "{user}@12345", "{user}#123", "{user}#123456", "{user}#12345",
                             "{user}_123", "{user}_123456", "{user}_12345", "{user}123!@#", "{user}!@#$", "{user}!@#",
                             "{user}~!@", "{user}!@#123", "qweasdzxc", "{user}2017", "{user}2016", "{user}2015",
                             "{user}@2017", "{user}@2016", "{user}@2015", "Passw0rd", "admin123!@#", "admin",
                             "admin123", "admin@123", "admin#123", "123456", "password", "12345", "1234", "root", "123",
                             "qwerty", "test", "1q2w3e4r", "1qaz2wsx", "qazwsx", "123qwe", "123qaz", "0000", "oracle",
                             "1234567", "123456qwerty", "password123", "12345678", "1q2w3e", "abc123", "okmnji",
                             "test123", "123456789", "postgres", "q1w2e3r4", "redhat", "user", "mysql", "apache"],
            },
            "Redis": {
                "user": [""],
                "password": ["Passw0rd", "admin", "{user}", "{user}123", "{user}1234", "{user}123456", "{user}12345",
                             "{user}@123", "{user}@123456", "{user}@12345", "{user}#123", "{user}#123456",
                             "{user}#12345", "{user}_123", "{user}_123456", "{user}_12345", "{user}123!@#",
                             "{user}!@#$", "{user}!@#", "{user}~!@", "{user}!@#123", "qweasdzxc", "{user}2017",
                             "{user}2016", "{user}2015", "{user}@2017", "{user}@2016", "{user}@2015", "admin123",
                             "admin888", "administrator", "administrator123", "root123", "123456", "password",
                             "12345", "1234", "root", "123", "qwerty", "test", "1q2w3e4r", "1qaz2wsx", "qazwsx",
                             "123qwe", "123qaz", "0000", "oracle", "1234567", "123456qwerty", "password123",
                             "12345678", "1q2w3e", "abc123", "okmnji", "test123", "123456789", "q1w2e3r4", "user",
                             "web", "foobared"],
            },
            "SMB": {
                "user": ["administrator", "admin", "test", "user", "manager", "webadmin", "guest", "db2admin"],
                "password": ["{user}", "{user}123", "{user}1234", "{user}123456", "{user}12345", "{user}@123",
                             "{user}@123456", "{user}@12345", "{user}#123", "{user}#123456", "{user}#12345",
                             "{user}_123", "{user}_123456", "{user}_12345", "{user}123!@#", "{user}!@#$", "{user}!@#",
                             "{user}~!@", "{user}!@#123", "qweasdzxc", "{user}2017", "{user}2016", "{user}2015",
                             "{user}@2017", "{user}@2016", "{user}@2015", "Passw0rd", "admin123!@#", "admin",
                             "admin123", "admin@123", "admin#123", "123456", "password", "12345", "1234", "root", "123",
                             "qwerty", "test", "1q2w3e4r", "1qaz2wsx", "qazwsx", "123qwe", "123qaz", "0000", "oracle",
                             "1234567", "123456qwerty", "password123", "12345678", "1q2w3e", "abc123", "okmnji",
                             "test123", "123456789", "postgres", "q1w2e3r4", "redhat", "user", "mysql", "apache"],
            },
            "SSH": {
                "user": ["root", "test", "oracle", "admin", "user", "mysql", "backup", "guest", "system", "web",
                         "guest", "tomcat", "upload", "sys", "sales", "linux", "ftp", "temp", "user1", "www",
                         "test1", ],
                "password": ["{user}", "{user}123", "{user}1234", "{user}123456", "{user}12345", "{user}@123",
                             "{user}@123456", "{user}@12345", "{user}#123", "{user}#123456", "{user}#12345",
                             "{user}_123", "{user}_123456", "{user}_12345", "{user}123!@#", "{user}!@#$", "{user}!@#",
                             "{user}~!@", "{user}!@#123", "qweasdzxc", "{user}2017", "{user}2016", "{user}2015",
                             "{user}@2017", "{user}@2016", "{user}@2015", "Passw0rd", "qweasdzxc", "admin123!@#",
                             "admin", "admin123", "admin@123", "admin#123", "123456", "password", "12345", "1234",
                             "root", "123", "qwerty", "test", "1q2w3e4r", "1qaz2wsx", "qazwsx", "123qwe", "123qaz",
                             "0000", "oracle", "1234567", "123456qwerty", "password123", "12345678", "1q2w3e", "abc123",
                             "okmnji", "test123", "123456789", "postgres", "q1w2e3r4", "redhat", "user", "mysql",
                             "apache", ""],
            },
            "VNC": {
                "user": [""],
                "password": ["{user}", "{user}123", "{user}1234", "{user}123456", "{user}12345", "{user}@123",
                             "{user}@123456", "{user}@12345", "{user}#123", "{user}#123456", "{user}#12345",
                             "{user}_123", "{user}_123456", "{user}_12345", "{user}123!@#", "{user}!@#$", "{user}!@#",
                             "{user}~!@", "{user}!@#123", "qweasdzxc", "{user}2017", "{user}2016", "{user}2015",
                             "{user}@2017", "{user}@2016", "{user}@2015", "qweasdzxc", "Passw0rd", "admin123",
                             "admin888", "administrator", "administrator123", "root123", "123456", "password", "12345",
                             "1234", "root", "123", "qwerty", "test", "1q2w3e4r", "1qaz2wsx", "qazwsx", "123qwe",
                             "123qaz", "0000", "oracle", "1234567", "123456qwerty", "password123", "12345678", "1q2w3e",
                             "abc123", "okmnji", "test123", "123456789", "q1w2e3r4", "qwer1234"],
            },
        }

        self.password_dict_empty = {
            "FTP": {
                "user": [],
                "password": [],
            },
            "MongoDB": {
                "user": [],
                "password": [],
            },
            "MSSQL": {
                "user": [],
                "password": [],
            },
            "MYSQL": {
                "user": [],
                "password": [],
            },
            "Memcached": {
                "user": [],
                "password": [],
            },
            "PostgreSQL": {
                "user": [],
                "password": [],
            },
            "RDP": {
                "user": [],
                "password": [],
            },
            "Redis": {
                "user": [],
                "password": [],
            },
            "SMB": {
                "user": [],
                "password": [],
            },
            "SSH": {
                "user": [],
                "password": [],
            },
            "VNC": {
                "user": [],
                "password": [],
            },
        }

        self.PostgreSQL_user_passwd_pair_list = []
        self.MongoDB_user_passwd_pair_list = []
        self.FTP_user_passwd_pair_list = []
        self.RDP_user_passwd_pair_list = []
        self.SMB_user_passwd_pair_list = []
        self.MYSQL_user_passwd_pair_list = []
        self.MSSQL_user_passwd_pair_list = []
        self.Redis_user_passwd_pair_list = []
        self.Memcached_user_passwd_pair_list = []
        self.VNC_user_passwd_pair_list = []
        self.SSH_user_passwd_pair_list = []

    def de_duplication(self, user_passwd_pair_list):
        templist = []
        for user_passwd_pair in user_passwd_pair_list:
            if user_passwd_pair[0] == "" or user_passwd_pair[0] == None:
                continue
            if user_passwd_pair not in templist:
                templist.append(user_passwd_pair)
        return templist

    def de_duplication_by_password(self, user_passwd_pair_list):
        """数据去重(针对只需要密码的数据list)"""
        templist = []
        for user_passwd_pair in user_passwd_pair_list:
            temp = ("", user_passwd_pair[1])
            if temp not in templist:
                templist.append(temp)
        return templist

    def init(self, default_dict, users, passwords):

        add_users = users
        add_passwords = passwords
        add_user_passwd_pair_list = []
        for user in add_users:
            for password in add_passwords:
                add_user_passwd_pair_list.append((user, password.format(user=user)))

        if default_dict:
            pass
        else:
            self.password_dict = self.password_dict_empty
        logger.info("------------------------------------")
        FTP_user_passwd_pair_list = add_user_passwd_pair_list
        data_user = self.password_dict.get("FTP").get("user")
        data_password = self.password_dict.get("FTP").get("password")
        for user in data_user:
            for password in data_password:
                FTP_user_passwd_pair_list.append((user, password.format(user=user)))
        old_len = len(FTP_user_passwd_pair_list)
        self.FTP_user_passwd_pair_list = self.de_duplication(FTP_user_passwd_pair_list)
        logger.info(
            "FTP_user_passwd_pair_list length: {} after de_duplication: {}".format(old_len,
                                                                                   len(self.FTP_user_passwd_pair_list)))

        MongoDB_user_passwd_pair_list = add_user_passwd_pair_list
        data_user = self.password_dict.get("MongoDB").get("user")
        data_password = self.password_dict.get("MongoDB").get("password")
        for user in data_user:
            for password in data_password:
                MongoDB_user_passwd_pair_list.append((user, password.format(user=user)))

        old_len = len(MongoDB_user_passwd_pair_list)
        self.MongoDB_user_passwd_pair_list = self.de_duplication(MongoDB_user_passwd_pair_list)
        logger.info(
            "MongoDB_user_passwd_pair_list length: {} after de_duplication: {}".format(old_len,
                                                                                       len(
                                                                                           self.MongoDB_user_passwd_pair_list)))

        MSSQL_user_passwd_pair_list = add_user_passwd_pair_list
        data_user = self.password_dict.get("MSSQL").get("user")
        data_password = self.password_dict.get("MSSQL").get("password")
        for user in data_user:
            for password in data_password:
                MSSQL_user_passwd_pair_list.append((user, password.format(user=user)))

        old_len = len(MSSQL_user_passwd_pair_list)
        self.MSSQL_user_passwd_pair_list = self.de_duplication(MSSQL_user_passwd_pair_list)
        logger.info(
            "MSSQL_user_passwd_pair_list length: {} after de_duplication: {}".format(old_len, len(
                self.MSSQL_user_passwd_pair_list)))

        MYSQL_user_passwd_pair_list = add_user_passwd_pair_list
        data_user = self.password_dict.get("MYSQL").get("user")
        data_password = self.password_dict.get("MYSQL").get("password")
        for user in data_user:
            for password in data_password:
                MYSQL_user_passwd_pair_list.append((user, password.format(user=user)))

        old_len = len(MYSQL_user_passwd_pair_list)
        self.MYSQL_user_passwd_pair_list = self.de_duplication(MYSQL_user_passwd_pair_list)
        logger.info(
            "MYSQL_user_passwd_pair_list length: {} after de_duplication: {}".format(old_len, len(
                self.MYSQL_user_passwd_pair_list)))

        Memcached_user_passwd_pair_list = add_user_passwd_pair_list
        data_user = self.password_dict.get("Memcached").get("user")
        data_password = self.password_dict.get("Memcached").get("password")
        for user in data_user:
            for password in data_password:
                Memcached_user_passwd_pair_list.append((user, password.format(user=user)))

        old_len = len(Memcached_user_passwd_pair_list)
        self.Memcached_user_passwd_pair_list = self.de_duplication(Memcached_user_passwd_pair_list)
        logger.info("Memcached_user_passwd_pair_list length: {} after de_duplication: {}".format(old_len,
                                                                                                 len(
                                                                                                     self.Memcached_user_passwd_pair_list)))

        PostgreSQL_user_passwd_pair_list = add_user_passwd_pair_list
        data_user = self.password_dict.get("PostgreSQL").get("user")
        data_password = self.password_dict.get("PostgreSQL").get("password")
        for user in data_user:
            for password in data_password:
                PostgreSQL_user_passwd_pair_list.append((user, password.format(user=user)))

        old_len = len(PostgreSQL_user_passwd_pair_list)
        self.PostgreSQL_user_passwd_pair_list = self.de_duplication(PostgreSQL_user_passwd_pair_list)
        logger.info("PostgreSQL_user_passwd_pair_list length: {} after de_duplication: {}".format(old_len,
                                                                                                  len(
                                                                                                      self.PostgreSQL_user_passwd_pair_list)))

        RDP_user_passwd_pair_list = add_user_passwd_pair_list
        data_user = self.password_dict.get("RDP").get("user")
        data_password = self.password_dict.get("RDP").get("password")
        for user in data_user:
            for password in data_password:
                RDP_user_passwd_pair_list.append((user, password.format(user=user)))

        old_len = len(RDP_user_passwd_pair_list)
        self.RDP_user_passwd_pair_list = self.de_duplication(RDP_user_passwd_pair_list)
        logger.info(
            "RDP_user_passwd_pair_list length: {} after de_duplication: {}".format(old_len,
                                                                                   len(self.RDP_user_passwd_pair_list)))

        SMB_user_passwd_pair_list = add_user_passwd_pair_list
        data_user = self.password_dict.get("SMB").get("user")
        data_password = self.password_dict.get("SMB").get("password")
        for user in data_user:
            for password in data_password:
                SMB_user_passwd_pair_list.append((user, password.format(user=user)))

        old_len = len(SMB_user_passwd_pair_list)
        self.SMB_user_passwd_pair_list = self.de_duplication(SMB_user_passwd_pair_list)
        logger.info(
            "SMB_user_passwd_pair_list length: {} after de_duplication: {}".format(old_len,
                                                                                   len(self.SMB_user_passwd_pair_list)))

        SSH_user_passwd_pair_list = add_user_passwd_pair_list
        data_user = self.password_dict.get("SSH").get("user")
        data_password = self.password_dict.get("SSH").get("password")
        for user in data_user:
            for password in data_password:
                SSH_user_passwd_pair_list.append((user, password.format(user=user)))

        old_len = len(SSH_user_passwd_pair_list)
        self.SSH_user_passwd_pair_list = self.de_duplication(SSH_user_passwd_pair_list)
        logger.info(
            "SSH_user_passwd_pair_list length: {} after de_duplication: {}".format(old_len,
                                                                                   len(self.SSH_user_passwd_pair_list)))

        Redis_user_passwd_pair_list = add_user_passwd_pair_list
        data_user = self.password_dict.get("Redis").get("user")
        data_password = self.password_dict.get("Redis").get("password")
        for user in data_user:
            for password in data_password:
                Redis_user_passwd_pair_list.append((user, password.format(user=user)))

        old_len = len(Redis_user_passwd_pair_list)
        self.Redis_user_passwd_pair_list = self.de_duplication_by_password(Redis_user_passwd_pair_list)
        logger.info(
            "Redis_user_passwd_pair_list length: {} after de_duplication: {}".format(old_len, len(
                self.Redis_user_passwd_pair_list)))

        VNC_user_passwd_pair_list = add_user_passwd_pair_list
        data_user = self.password_dict.get("VNC").get("user")
        data_password = self.password_dict.get("VNC").get("password")
        for user in data_user:
            for password in data_password:
                VNC_user_passwd_pair_list.append((user, password.format(user=user)))

        old_len = len(VNC_user_passwd_pair_list)
        self.VNC_user_passwd_pair_list = self.de_duplication_by_password(VNC_user_passwd_pair_list)
        logger.info(
            "VNC_user_passwd_pair_list length: {} after de_duplication: {}".format(old_len,
                                                                                   len(self.VNC_user_passwd_pair_list)))
        logger.info("------------------------------------")
