# -*- coding: utf-8 -*-
import flask, flask.testing
import pytest
from api.config import GlobalConfig
from utility import DefaultPassword, runAuth, runGetUser, runModifyUser, verifyResponse
from utility import createUser, removeUser


def setup_function() -> None:
    """Testing setup."""
    createUser('test1@testing.com', DefaultPassword)
    createUser('test2@testing.com', DefaultPassword)

def teardown_function() -> None:
    """Testing teardown."""
    removeUser('test1@testing.com')
    removeUser('test2@testing.com')

def test_modify_user_no_auth_invalid_format(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth and invalid format."""
    result = runModifyUser(client, 'nonono', '', payload={
            'password': 'xxxxx'
        })
    verifyResponse(client, result, 401, 'modify')

def test_modify_user_no_auth(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth."""
    result = runModifyUser(client, 'test1@testing.com', '', payload={
            'password': 'xxxxx'
        })
    verifyResponse(client, result, 401, 'modify')

def test_modfiy_user_wrong_auth_header(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test invalid header."""
    result = runModifyUser(
        client, 'nonono', 'fdj;fklasdjf9iopqwejfl;asdkfasdjf.werwqer.2282828',
        payload={'password': DefaultPassword})
    verifyResponse(client, result, 401, 'modify')

def test_modify_admin_modify_user_password(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create normal user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runModifyUser(
        client, 'test2@testing.com', jwt=jwt,
        payload={'password': 'new-password'})
    verifyResponse(client, result, 200, 'modify')
    result = runGetUser(client, 'test2@testing.com', jwt=jwt)
    verifyResponse(client, result, 200, 'getuser', {
        'password': 'new-password'
    })

def test_modify_admin_modify_user_password_status(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create normal user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runModifyUser(
        client, 'test2@testing.com', jwt=jwt,
        payload={'password': 'new-password', 'status': 0})
    verifyResponse(client, result, 200, 'modify')
    result = runGetUser(client, 'test2@testing.com', jwt=jwt)
    verifyResponse(client, result, 200, 'getuser', {
        'password': 'new-password',
        'status': 0
    })

def test_modify_admin_modify_user_password_status_wrong_format(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create normal user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runModifyUser(
        client, 'test2@testing.com', jwt=jwt,
        payload={'password': 12345, 'status': 'not string'})
    verifyResponse(client, result, 400, 'modify')

def test_modify_user_modify_self_password(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create normal user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runModifyUser(
        client, 'test1@testing.com', jwt=jwt,
        payload={'password': 'new-password'})
    verifyResponse(client, result, 200, 'modify')
    result = runGetUser(client, 'test1@testing.com', jwt=jwt)
    verifyResponse(client, result, 200, 'getuser', {
        'password': 'new-password'
    })

def test_modify_user_modify_self_password_status(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create normal user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runModifyUser(
        client, 'test1@testing.com', jwt=jwt,
        payload={'password': 'new-password', 'status': 0})
    verifyResponse(client, result, 200, 'modify')
    result = runGetUser(client, 'test1@testing.com', jwt=jwt)
    verifyResponse(client, result, 200, 'getuser', {
        'password': 'new-password',
        'status': 0
    })

def test_modify_user_modify_self_password_status_wrong_format(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create normal user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runModifyUser(
        client, 'test1@testing.com', jwt=jwt,
        payload={'password': 12345, 'status': 'not string'})
    verifyResponse(client, result, 400, 'modify')

def test_modify_user_modify_other_password_status(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create normal user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runModifyUser(
        client, 'test2@testing.com', jwt=jwt,
        payload={'password': 'new-password', 'status': 0})
    verifyResponse(client, result, 403, 'modify')

def test_modify_user_modify_other_password_status_wrong_format(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create normal user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runModifyUser(
        client, 'test2@testing.com', jwt=jwt,
        payload={'password': 12345, 'status': 'not string'})
    verifyResponse(client, result, 403, 'modify')

def test_modify_user_not_exist(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runModifyUser(
        client, 'nonono@testing.com', jwt=jwt,
        payload={'password': 'new-password', 'status': 0})
    verifyResponse(client, result, 404, 'modify')
    result = runGetUser(client, 'nonono@testing.com', jwt=jwt)
    verifyResponse(client, result, 404, 'getuser')
