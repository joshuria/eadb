# -*- coding: utf-8 -*-
import flask, flask.testing
import pytest
from api.config import GlobalConfig
from api.model import Status
from utility import DefaultPassword
from utility import runAuth, verifyResponse, createUser, removeUser


def setup_function() -> None:
    """Testing setup."""
    createUser('test1@testing.com', DefaultPassword)
    createUser('test2@testing.com', DefaultPassword, Status.Disabled)

def teardown_function() -> None:
    """Testing teardown."""
    removeUser('test1@testing.com')
    removeUser('test2@testing.com')

def test_auth_admin(client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture) -> None:
    """Test admin normal auth."""
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

def test_auth_admin_login(client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture) -> None:
    """Test admin normal login."""
    result = runAuth(client, urlLogin='/1', payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth', expectDataContains={
        'createTime', 'lastLoginTime', 'lastLoginIp', 'eaStatus', 'log'
    })

def test_auth_admin_invalid_url_param(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin auth with invalid url parameter."""
    result = runAuth(client, urlLogin='/invalid/url/param/333', payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 404, 'auth')

def test_auth_admin_login_with_extra_url_parameter(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin auth with invalid url parameter."""
    result = runAuth(client, urlLogin='/0', extraUrl='/extra/url/333', payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 404, 'auth')

def test_auth_not_exist(client: flask.testing.FlaskClient, capsys) -> None:
    """Test auth with non-exist user."""
    result = runAuth(client, payload={
        'userId': 'nononono',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 404, 'auth')

def test_auth_missing_parameter(client: flask.testing.FlaskClient, capsys):
    """Test auth with no payload."""
    result = runAuth(client)
    verifyResponse(client, result, 400, 'auth')

def test_auth_missing_userId(client: flask.testing.FlaskClient, capsys):
    """Test auth without given userId."""
    result = runAuth(client, payload={
        'password': DefaultPassword
    })
    verifyResponse(client, result, 400, 'auth')

def test_auth_missing_password(client: flask.testing.FlaskClient, capsys):
    """Test auth without given password."""
    result = runAuth(client, payload={
        'userId': 'nononono'
    })
    verifyResponse(client, result, 400, 'auth')

def test_auth_missing_header(client: flask.testing.FlaskClient, capsys):
    """Test auth missing header ."""
    result = runAuth(client, payload={
            'userId': 'nononono'
        }, headers={
            'User-Agent': 'testing-api-user-agent',
            'x-access-name': 'testing-case-api',
            'x-access-version': '0.0.1',
        })
    verifyResponse(client, result, 400, 'auth')

def test_auth_normal_user(client: flask.testing.FlaskClient, capsys):
    """Test auth normal user."""
    result = runAuth(client, payload={
            'userId': 'test1@testing.com',
            'password': DefaultPassword
        })
    verifyResponse(client, result, 200, 'auth')

def test_auth_disabled_user(client: flask.testing.FlaskClient, capsys):
    """Test auth disabled user."""
    result = runAuth(client, payload={
            'userId': 'test2@testing.com',
            'password': DefaultPassword
        })
    verifyResponse(client, result, 403, 'auth')

def test_auth_normal_user_login(client: flask.testing.FlaskClient, capsys):
    """Test login normal user."""
    result = runAuth(client, urlLogin='/1', payload={
            'userId': 'test1@testing.com',
            'password': DefaultPassword
        })
    verifyResponse(client, result, 200, 'auth', expectDataContains={
        'createTime', 'lastLoginTime', 'lastLoginIp', 'eaStatus', 'log'
    })

def test_auth_disabled_user_login(client: flask.testing.FlaskClient, capsys):
    """Test login disabled user."""
    result = runAuth(client, urlLogin='/1', payload={
            'userId': 'test2@testing.com',
            'password': DefaultPassword
        })
    verifyResponse(client, result, 403, 'auth')
