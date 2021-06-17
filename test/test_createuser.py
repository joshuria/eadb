# -*- coding: utf-8 -*-
import os
from api.config import GlobalConfig
from conftest import DefaultPassword, runAuth, runCreateUser, verifyResponse


def test_create_user_no_auth_invalid_format(client, capsys):
    result = runCreateUser(client, 'nonono', {
            'password': 'xxxxx'
        })
    verifyResponse(client, result, 401, 'create')

def test_create_user_no_auth(client, capsys):
    result = runCreateUser(client, 'nonono@testing.com', {
            'password': 'xxxxx'
        })
    verifyResponse(client, result, 401, 'create')

def test_create_user_wrong_auth_header(client, capsys):
    result = runCreateUser(client, 'nonono', {
            'password': DefaultPassword
        }, {
            'User-Agent': 'testing-api-user-agent',
            'x-access-apikey': os.getenv('API_KEYS', ''),
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
            'Authorization': 'Bearer fdj;fklasdjf9iopqwejfl;asdkfasdjf.werwqer.2282828'
        })
    verifyResponse(client, result, 401, 'create')

def test_create_user_correct(client, capsys):
    result = runAuth(client, {
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

    result = runCreateUser(client, 'test-user@testing.com', {
            'password': DefaultPassword
        }, {
            'User-Agent': 'testing-api-user-agent',
            'x-access-apikey': os.getenv('API_KEYS', ''),
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
            'Authorization': 'Bearer %s' % result.headers['JWT']
        })
    verifyResponse(client, result, 200, 'create')

def test_create_user_non_admin(client, capsys):
    result = runAuth(client, {
        'userId': 'test-user@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

    result = runCreateUser(client, 'test-user1@testing.com', {
            'userId': 'test-user1@testing.com',
            'password': DefaultPassword
        }, {
            'User-Agent': 'testing-api-user-agent',
            'x-access-apikey': os.getenv('API_KEYS', ''),
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
            'Authorization': 'Bearer %s' % result.headers['JWT']
        })
    verifyResponse(client, result, 403, 'create')

def test_create_user_exist(client, capsys):
    result = runAuth(client, {
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

    result = runCreateUser(client, 'test-user@testing.com', {
            'userId': 'test-user@testing.com',
            'password': DefaultPassword
        }, {
            'User-Agent': 'testing-api-user-agent',
            'x-access-apikey': os.getenv('API_KEYS', ''),
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
            'Authorization': 'Bearer %s' % result.headers['JWT']
        })
    verifyResponse(client, result, 409, 'create')
