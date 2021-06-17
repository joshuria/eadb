# -*- coding: utf-8 -*-
import os
import sys
import json
import urllib.parse

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
)

import pytest
from app import create_app
from api.config import GlobalConfig

@pytest.fixture
def client():
    app = create_app(True)
    client = app.test_client()
    cxt = app.app_context()
    cxt.push()
    yield client
    cxt.pop()

GeneralHeader = {
    'User-Agent': 'testing-api-user-agent',
    'x-access-apikey': os.getenv('API_KEYS', ''),
    'x-access-name': 'testing-case-api',
    'x-access-version': '0.0.1',
}
DefaultPassword = 'xyzzy'

def verifyResponse(client, response, expectStatusCode: int, operation: str):
    print(' ======== %s =======' % operation)
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
    assert response.status_code == expectStatusCode, \
        '%s: resp %s != exp %d ' % (operation, response.status, expectStatusCode)

def runAuth(client, payload=None, customHeader=None):
    return client.post(
        '/api/v1/auth',
        content_type='application/json',
        headers=customHeader if customHeader is not None else GeneralHeader,
        data=json.dumps(payload))

def runCreateUser(client, userId: str, payload=None, customHeader=None):
    return client.post(
        urllib.parse.urljoin('/api/v1/user/', userId),
        content_type='application/json',
        headers=customHeader if customHeader is not None else GeneralHeader,
        data=json.dumps(payload))
