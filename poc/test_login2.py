#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 NAC 真实密码（VSG_PWD 解密值）测试登录。"""
import sys
sys.path.insert(0, '.')
import nac_client_mvp as m
import requests

# NAC 账号密码候选（VSG_PWD 解密值 <NAC_PASSWORD>）
pwd_candidates = [
    '<NAC_PASSWORD>',
    '<NAC_PASSWORD>',
    '<DOMAIN_PASSWORD>',
]

for pwd in pwd_candidates:
    m.CONFIG['username'] = '<NAC_USERNAME>'
    m.CONFIG['password'] = pwd
    s = requests.Session()
    print('=' * 50)
    print('尝试 username=<NAC_USERNAME> password=%r' % pwd)
    try:
        r = m.login(s)
        sid = r.get('sessionid', '')
        print('  -> sessionid=%r' % sid)
        if sid and sid != '0':
            print('  >>> 登录成功！sessionid=%s' % sid)
            break
    except Exception as e:
        print('  -> 异常: %r' % e)
    print()
