# -*- coding: utf-8 -*-
from typing import List, Tuple, Callable
import flask.testing
import json
from api.config import GlobalConfig
from api.model import Status, User, LogOperation
from test.utility import createUsers, addLogs, getUser, runBuyLicense
from test.utility import DefaultPassword, GeneralHeader
from test.utility import runAuth, verifyResponse


def test_auth_admin(createUsers: Tuple[flask.testing.FlaskClient, Callable]) -> None:
    """Test admin normal auth."""
    client, userCreator = createUsers
    users = userCreator(['test1@testing.com', 'test2@testing.com']) # type: List[User]
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

    result = runAuth(client, urlLogin='/0', payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    assert len(result.json) == 0, 'auth: unexpected extra response'

def test_buy_license(createUsers: Tuple[flask.testing.FlaskClient, Callable]) -> None:
    client, userCreator = createUsers
    users = userCreator(['test1@testing.com', 'test2@testing.com']) # type: List[User]

    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']

    result = runBuyLicense(client, jwt, payload=[
        {'broker': 'broker1', 'eaId': 'idid1', 'count': 10, 'duration': 10},
        {'broker': 'broker1', 'eaId': 'idid2', 'count': 10, 'duration': 20}
    ])
    print('response: ', result.json)
    verifyResponse(client, result, 200, 'buyLicense')

# def test_auth_admin_login(client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture) -> None:
#     """Test admin normal login."""
#     result = runAuth(client, urlLogin='/1', payload={
#         'userId': GlobalConfig.DbDefaultAdmin,
#         'password': DefaultPassword
#     })
#     verifyResponse(client, result, 200, 'auth', expectDataContains={
#         'createTime', 'lastLoginTime', 'lastLoginIp', 'eaStatus', 'log'
#     })

# def test_auth_admin_invalid_url_param(
#     client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
# ) -> None:
#     """Test admin auth with invalid url parameter."""
#     result = runAuth(client, urlLogin='/invalid/url/param/333', payload={
#         'userId': GlobalConfig.DbDefaultAdmin,
#         'password': DefaultPassword
#     })
#     verifyResponse(client, result, 404, 'auth')

# def test_auth_admin_login_with_extra_url_parameter(
#     client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
# ) -> None:
#     """Test admin auth with invalid url parameter."""
#     result = runAuth(client, urlLogin='/0', extraUrl='/extra/url/333', payload={
#         'userId': GlobalConfig.DbDefaultAdmin,
#         'password': DefaultPassword
#     })
#     verifyResponse(client, result, 404, 'auth')

# def test_auth_not_exist(client: flask.testing.FlaskClient, capsys) -> None:
#     """Test auth with non-exist user."""
#     result = runAuth(client, payload={
#         'userId': 'nononono',
#         'password': DefaultPassword
#     })
#     verifyResponse(client, result, 404, 'auth')

# def test_auth_missing_parameter(client: flask.testing.FlaskClient, capsys):
#     """Test auth with no payload."""
#     result = runAuth(client)
#     verifyResponse(client, result, 400, 'auth')

# def test_auth_missing_userId(client: flask.testing.FlaskClient, capsys):
#     """Test auth without given userId."""
#     result = runAuth(client, payload={
#         'password': DefaultPassword
#     })
#     verifyResponse(client, result, 400, 'auth')

# def test_auth_missing_password(client: flask.testing.FlaskClient, capsys):
#     """Test auth without given password."""
#     result = runAuth(client, payload={
#         'userId': 'nononono'
#     })
#     verifyResponse(client, result, 400, 'auth')

# def test_auth_missing_header(client: flask.testing.FlaskClient, capsys):
#     """Test auth missing header ."""
#     result = runAuth(client, payload={
#             'userId': 'nononono'
#         }, headers={
#             'User-Agent': 'testing-api-user-agent',
#             'x-access-name': 'testing-case-api',
#             'x-access-version': '0.0.1',
#         })
#     verifyResponse(client, result, 400, 'auth')

# def test_auth_normal_user(client: flask.testing.FlaskClient, capsys):
#     """Test auth normal user."""
#     result = runAuth(client, payload={
#             'userId': 'test1@testing.com',
#             'password': DefaultPassword
#         })
#     verifyResponse(client, result, 200, 'auth')

# def test_auth_disabled_user(client: flask.testing.FlaskClient, capsys):
#     """Test auth disabled user."""
#     result = runAuth(client, payload={
#             'userId': 'test2@testing.com',
#             'password': DefaultPassword
#         })
#     verifyResponse(client, result, 403, 'auth')

# def test_auth_normal_user_login(client: flask.testing.FlaskClient, capsys):
#     """Test login normal user."""
#     result = runAuth(client, urlLogin='/1', payload={
#             'userId': 'test1@testing.com',
#             'password': DefaultPassword
#         })
#     verifyResponse(client, result, 200, 'auth', expectDataContains={
#         'createTime', 'lastLoginTime', 'lastLoginIp', 'eaStatus', 'log'
#     })
#     print(result.json['log'][0]['timestamp'])
#     assert False

# def test_auth_disabled_user_login(client: flask.testing.FlaskClient, capsys):
#     """Test login disabled user."""
#     result = runAuth(client, urlLogin='/1', payload={
#             'userId': 'test2@testing.com',
#             'password': DefaultPassword
#         })
#     verifyResponse(client, result, 403, 'auth')
