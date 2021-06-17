# -*- coding: utf-8 -*-
import os
from api.config import GlobalConfig
from conftest import DefaultPassword, runAuth, runGetUser, verifyResponse
from conftest import createUser, removeUser


def setup_function():
    createUser('test1@testing.com', DefaultPassword)
    createUser('test2@testing.com', DefaultPassword)

def teardown_function():
    removeUser('test1@testing.com')
    removeUser('test2@testing.com')

def test_get_user_no_auth_invalid_format(client, capsys):
    result = runGetUser(client, 'nonono')
    verifyResponse(client, result, 401, 'getuser')

def test_get_user_no_auth(client, capsys):
    result = runGetUser(client, 'nonono@testing.com')
    verifyResponse(client, result, 401, 'getuser')

def test_get_user_wrong_auth_header(client, capsys):
    result = runGetUser(client, 'nonono@testing.com',  customHeader={
            'User-Agent': 'testing-api-user-agent',
            'x-access-apikey': os.getenv('API_KEYS', ''),
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
            'Authorization': 'Bearer fdj;fklasdjf9iopqwejfl;asdkfasdjf.werwqer.2282828'
        })
    verifyResponse(client, result, 401, 'getuser')

def test_get_user_admin_get_self(client, capsys):
    result = runAuth(client, {
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

    result = runGetUser(client, GlobalConfig.DbDefaultAdmin, customHeader={
            'User-Agent': 'testing-api-user-agent',
            'x-access-apikey': os.getenv('API_KEYS', ''),
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
            'Authorization': 'Bearer %s' % result.headers['JWT']
        })
    verifyResponse(client, result, 400, 'getuser')

def test_get_user_normal_get_self(client, capsys):
    result = runAuth(client, {
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

    result = runGetUser(client, 'test1@testing.com', customHeader={
            'User-Agent': 'testing-api-user-agent',
            'x-access-apikey': os.getenv('API_KEYS', ''),
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
            'Authorization': 'Bearer %s' % result.headers['JWT']
        })
    verifyResponse(client, result, 200, 'getuser')

def test_get_user_admin_get_other(client, capsys):
    result = runAuth(client, {
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

    result = runGetUser(client, 'test1@testing.com', customHeader={
            'User-Agent': 'testing-api-user-agent',
            'x-access-apikey': os.getenv('API_KEYS', ''),
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
            'Authorization': 'Bearer %s' % result.headers['JWT']
        })
    verifyResponse(client, result, 200, 'getuser')

def test_get_user_admin_get_other_not_exist(client, capsys):
    result = runAuth(client, {
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

    result = runGetUser(client, 'nonono@testing.com', customHeader={
            'User-Agent': 'testing-api-user-agent',
            'x-access-apikey': os.getenv('API_KEYS', ''),
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
            'Authorization': 'Bearer %s' % result.headers['JWT']
        })
    verifyResponse(client, result, 404, 'getuser')

def test_get_user_normal_get_other(client, capsys):
    result = runAuth(client, {
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

    result = runGetUser(client, 'test2@testing.com', customHeader={
            'User-Agent': 'testing-api-user-agent',
            'x-access-apikey': os.getenv('API_KEYS', ''),
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
            'Authorization': 'Bearer %s' % result.headers['JWT']
        })
    verifyResponse(client, result, 403, 'getuser')

def test_get_user_normal_get_other_not_exist(client, capsys):
    result = runAuth(client, {
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

    result = runGetUser(client, 'nonono@testing.com', customHeader={
            'User-Agent': 'testing-api-user-agent',
            'x-access-apikey': os.getenv('API_KEYS', ''),
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
            'Authorization': 'Bearer %s' % result.headers['JWT']
        })
    verifyResponse(client, result, 403, 'getuser')
