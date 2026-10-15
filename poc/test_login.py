#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试 AD 域登录：不同用户名格式 + 密码，看能否拿到 sessionid。"""
import sys
sys.path.insert(0, '.')
import nac_client_mvp as m
import requests

# 候选用户名格式
candidates = [
    '<DOMAIN_USER>',
    '<NAC_USERNAME>',
    '<DOMAIN>\\<DOMAIN_USER>',
    '<DOMAIN_USER>@<DOMAIN>',
    '<DOMAIN>/<DOMAIN_USER>',
]

for uname in candidates:
    m.CONFIG['username'] = uname
    m.CONFIG['password'] = '<DOMAIN_PASSWORD>'
    s = requests.Session()
    print('=' * 50)
    print('尝试登录 username=%r' % uname)
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
