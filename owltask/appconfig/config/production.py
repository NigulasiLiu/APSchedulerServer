# -*- coding: utf-8 -*-
# @version        : 1.0
# @Create Time    : 2021/10/19 15:47
# @File           : production.py
# @IDE            : PyCharm
# @desc           : 数据库开发配置文件

"""
MySQL 数据库配置

格式：mysql://用户名:密码@地址:端口/数据库名称
"""
MYSQL_DB_ENABLE = True
MYSQL_DB_NAME = "hids"
MYSQL_DB_USER = "root"
MYSQL_DB_PASSWORD = "liubq"
MYSQL_DB_HOST = "localhost"
MYSQL_DB_PORT = 3306
MYSQL_DB_URL = f"mysql://{MYSQL_DB_USER}:{MYSQL_DB_PASSWORD}@{MYSQL_DB_HOST}:{MYSQL_DB_PORT}/{MYSQL_DB_NAME}"