# -*- coding: utf-8 -*-
import json
import os
from api.config import GlobalConfig


GeneralHeader = {
    'User-Agent': 'testing-api-user-agent',
    'x-access-apikey': os.getenv('API_KEYS', ''),
    'x-access-name': 'testing-case-api',
    'x-access-version': '0.0.1',
}
DefaultPassword = 'xyzzy'

def _runAuth(client, payload=None, customHeader=None):
    return client.post(
        '/api/v1/auth',
        content_type='application/json',
        headers=customHeader if customHeader is not None else GeneralHeader,
        data=json.dumps(payload))

def _verifyResponse(client, response, expectStatusCode: int):
    print('Response status code: ', response.status)
    print('Response content type: ', response.content_type)
    try:
        print('Response data as json: ', response.json)
    except:
        print('Response data is not json: ', response.data)
    if 'JWT' in response.headers:
        print('Response JWT: ', response.headers['JWT'])
    else:
        print('Response no JWT')
    assert response.status_code == expectStatusCode

def test_auth_admin(client, capsys):
    result = _runAuth(client, {
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    _verifyResponse(client, result, 200)

def test_auth_not_exist(client, capsys):
    result = _runAuth(client, {
        'userId': 'nononono',
        'password': DefaultPassword
    })
    _verifyResponse(client, result, 404)

def test_auth_missing_userId(client, capsys):
    result = _runAuth(client, {
        'password': DefaultPassword
    })
    _verifyResponse(client, result, 400)

def test_auth_missing_password(client, capsys):
    result = _runAuth(client, {
        'userId': 'nononono'
    })
    _verifyResponse(client, result, 400)

def test_auth_missing_header(client, capsys):
    result = _runAuth(client, {
            'userId': 'nononono'
        }, {
            'User-Agent': 'testing-api-user-agent',
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
        })
    _verifyResponse(client, result, 400)
