# -*- coding: utf-8 -*-
import flask, flask.testing
import pytest
from api.config import GlobalConfig
from utility import DefaultPassword
from utility import runAuth, runGetUser, verifyResponse, createUser, removeUser


def setup_function() -> None:
    """Testing setup."""
    createUser('test1@testing.com', DefaultPassword)
    createUser('test2@testing.com', DefaultPassword)

def teardown_function() -> None:
    """Testing teardown."""
    removeUser('test1@testing.com')
    removeUser('test2@testing.com')

def test_get_user_no_auth_invalid_format(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test get non-exist user without auth."""
    result = runGetUser(client, 'nonono', '')
    verifyResponse(client, result, 401, 'getuser')

def test_get_user_no_auth(client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture) -> None:
    """Test get user withotu auth."""
    result = runGetUser(client, 'nonono@testing.com', '')
    verifyResponse(client, result, 401, 'getuser')

def test_get_user_wrong_auth_header(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test get user with invalid JWT."""
    result = runGetUser(
        client, 'nonono@testing.com',
        jwt='fdj;fklasdjf9iopqwejfl;asdkfasdjf.werwqer.2282828')
    verifyResponse(client, result, 401, 'getuser')

def test_get_user_admin_get_self(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin get admin self."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    result = runGetUser(client, GlobalConfig.DbDefaultAdmin, jwt=result.headers['JWT'])
    verifyResponse(client, result, 400, 'getuser')

def test_get_user_normal_get_self(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test normal user get self."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    result = runGetUser(client, 'test1@testing.com', jwt=result.headers['JWT'])
    verifyResponse(client, result, 200, 'getuser')

def test_get_user_admin_get_other(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin get other user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    result = runGetUser(client, 'test1@testing.com', jwt=result.headers['JWT'])
    verifyResponse(client, result, 200, 'getuser')

def test_get_user_admin_get_other_not_exist(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin get non-exist user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    result = runGetUser(client, 'nonono@testing.com', jwt=result.headers['JWT'])
    verifyResponse(client, result, 404, 'getuser')

def test_get_user_normal_get_other(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test normal user get others."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    result = runGetUser(client, 'test2@testing.com', jwt=result.headers['JWT'])
    verifyResponse(client, result, 403, 'getuser')

def test_get_user_normal_get_other_not_exist(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test normal user get non-exist user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    result = runGetUser(client, 'nonono@testing.com', jwt=result.headers['JWT'])
    verifyResponse(client, result, 403, 'getuser')
