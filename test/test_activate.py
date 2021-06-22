# -*- coding: utf-8 -*-
import flask, flask.testing
from typing import Dict, List, Tuple
import pytest
from api.config import GlobalConfig
from api.timefunction import toUTCDateTime
from utility import DefaultPassword, addLicense, runActivate, runAuth, runGetUser, runGetUserLog, runQueryLicense, verifyResponse
from utility import createUser, removeUser
from utility import getUser


# user -> {license -> (eatype, duration)}
licenseData = {}  # type: Dict[str, Dict[str, Tuple(int, int)]]
allLicenses = {}  # type: Dict[str, Tuple(int, int)]


def addLicenseToUser(user: str, count: int, eatype: int, duration: int) -> None:
    """Add a list of licenses to user and track in licenseData."""
    lic = addLicense(user, count, eatype, duration)
    if user not in licenseData:
        licenseData[user] = {}
    for l in lic:
        licenseData[user][l['lid']] = (eatype, duration)
        allLicenses[l['lid']] = (eatype, duration)

def setup_function() -> None:
    """Testing setup."""
    createUser('test1@testing.com', DefaultPassword)
    createUser('test2@testing.com', DefaultPassword)
    addLicenseToUser('test1@testing.com', 100, 111, 10)
    addLicenseToUser('test1@testing.com', 100, 222, 10)
    addLicenseToUser('test1@testing.com', 100, 333, 10)
    addLicense('test2@testing.com', 10, 111, 30)
    addLicenseToUser('test1@testing.com', 10, 111, 20)
    addLicenseToUser('test1@testing.com', 10, 222, 30)

def teardown_function() -> None:
    """Testing teardown."""
    removeUser('test1@testing.com')
    removeUser('test2@testing.com')
    licenseData.clear()
    allLicenses.clear()

def verifyEAStatus(
    activateResponse: flask.Response, userId: str, statusWholeEqual: bool=True
) -> None:
    """Verify activate result with user's data."""
    responseStatus = activateResponse.json['eaStatus']
    consumedLicense = activateResponse.json['license']
    user = getUser(userId)
    # Construct receivedEAStatus
    eaStatus = {}
    for s in responseStatus:
        assert s['eaType'] not in eaStatus, "Response eaType %s duplicated." % s['eaType']
        eaStatus[s['eaType']] = s['expireTime']
    # Construct realEAStatus
    realStatus = {}
    for s in user['eaStatus']:
        assert s['eaType'] not in realStatus, "Real user eaType %s duplicated." % s['eaType']
        realStatus[s['eaType']] = toUTCDateTime(s['expireTime'])
    # Verify ea status
    if statusWholeEqual:
        assert eaStatus.keys() == realStatus.keys(), "EA types not match"
    for t, e in eaStatus.items():
        assert t in realStatus, "Response ea type %s not in user real data" % t
        print()
        assert abs(e - realStatus[t].timestamp() * 1000) < 3000, \
            'Type %s expire time > 3s: %f, (re)%f' % (t, e, realStatus[t].timestamp() * 1000)
    # Verify all licenses are consumed
    gainDuration = {}  # type: Dict[int, int]
    for l in consumedLicense:
        lid, code = l['id'], l['result']
        assert lid in allLicenses, 'License %s does not eixst' % lid
        eatype, duration = allLicenses[lid]
        assert code == 0, 'License %s activate fail' % lid
        if eatype not in gainDuration: gainDuration[eatype] = 0
        gainDuration[eatype] += duration * 24 * 60 * 60 * 1000
        # TODO verify license record of owner user
    # Verify gained ea state
    for eatype, duration in gainDuration.items():
        assert abs(user['createTime'].timestamp() + duration - realStatus[eatype].timestamp() * 1000 <= 5000), \
            'Gained duration of type %d over 5s' % eatype

def test_activate_no_auth_invalid_format(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth and invalid format."""
    result = runActivate(client, 'nonono', '')
    verifyResponse(client, result, 401, 'activate')

def test_activate_no_auth(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth."""
    size = 15
    lic = [l for l in allLicenses.keys()][:size]
    result = runActivate(client, 'test1@testing.com', '', payload={'param': lic})
    verifyResponse(client, result, 401, 'activate')

def test_activate_wrong_auth_header(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test invalid header."""
    size = 15
    lic = [l for l in allLicenses.keys()][:size]
    result = runActivate(
        client, 'test1@testing.com',
        'fdj;fklasdjf9iopqwejfl;asdkfasdjf.werwqer.2282828',
        payload={'param': lic})
    verifyResponse(client, result, 401, 'activate')

def test_activate_admin(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    size = 2
    lic = [l for l in allLicenses.keys()][:size]
    result = runActivate(client, 'test1@testing.com', jwt=jwt, payload={'param': lic})
    verifyResponse(client, result, 200, 'activate')
    verifyEAStatus(result, 'test1@testing.com')

def test_query_license_self(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    size = 1
    lic = [l for l in allLicenses.keys()][:size]
    result = runActivate(client, 'test1@testing.com', jwt=jwt, payload={'param': lic})
    verifyResponse(client, result, 200, 'activate')
    verifyEAStatus(result, 'test1@testing.com')
