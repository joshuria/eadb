# -*- coding: utf-8 -*-
import json
from api.config import GlobalConfig
from conftest import DefaultPassword, runAuth, verifyResponse


def test_auth_admin(client, capsys):
    result = runAuth(client, {
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

def test_auth_not_exist(client, capsys):
    result = runAuth(client, {
        'userId': 'nononono',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 404, 'auth')

def test_auth_missing_userId(client, capsys):
    result = runAuth(client, {
        'password': DefaultPassword
    })
    verifyResponse(client, result, 400, 'auth')

def test_auth_missing_password(client, capsys):
    result = runAuth(client, {
        'userId': 'nononono'
    })
    verifyResponse(client, result, 400, 'auth')

def test_auth_missing_header(client, capsys):
    result = runAuth(client, {
            'userId': 'nononono'
        }, {
            'User-Agent': 'testing-api-user-agent',
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
        })
    verifyResponse(client, result, 400, 'auth')
