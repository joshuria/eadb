# -*- coding: utf-8 -*-
"""Defines global database instance."""
from __future__ import print_function
import time
from typing import Any, Dict, Collection, List, Tuple
from flask.helpers import make_response

from flask.json import jsonify
from config import GlobalConfig
from flask_pymongo import PyMongo
from pymongo import ASCENDING, DESCENDING


db = PyMongo()

def initializeDb(app) -> None:
    """Initialize db instance."""
    db.init_app(app)
    _initializeUserCollection()
    _initializeLicenseCollection()
    _initializeJWTCollection()

def _initializeUserCollection() -> None:
    """Initialize the user collection with default account and indices."""
    userCol = db.db.user
    if GlobalConfig.DbName not in db.cx.list_database_names():
        print('Create database with name: ' + GlobalConfig.DbName)
        now = round(time.time() * 1000)
        # raise DuplicateKeyError if already exist
        userCol.insert_one({
            '_id': GlobalConfig.DbDefaultAdmin,
            'password': 'xyzzy',
            'createTime': now,
            'lastLoginTime': 0,
            'lastLoginIp': '',
            'status': 1,
            'order': [],
            'eaStatus': [],
            'log': [{
                "timestamp": now,
                "operation": 0x10,
                "ip": "",
                "user": ""
            }]
        })

    userColIndices = userCol.index_information()
    _createIndex(
        name='userOrderEATypeBuyTimeIndex',
        constraints=[
            ('order.eaType', ASCENDING),
            ('order.buyTime', DESCENDING)
        ],
        indexDict=userColIndices, collection=userCol)
    _createIndex(
        name='userLogTimestampOperationIndex',
        constraints=[
            ('log.timestamp', DESCENDING),
            ('log.operation', ASCENDING)
        ],
        indexDict=userColIndices, collection=userCol)
    _createIndex(
        name='userLogTimestampTTLIndex',
        constraints=[('log.timestamp', DESCENDING)],
        indexDict=userColIndices, collection=userCol,
        expireAfterSeconds=GlobalConfig.DbUserLogExpireDay * 24 * 60 * 60)

def _initializeLicenseCollection() -> None:
    """Initialize the License collection with default value and indices."""
    licCol = db.db.license
    licColIndices = licCol.index_information()
    _createIndex(
        name='licenseOwnerBuyTimeIndex',
        constraints=[
            ('owner', ASCENDING),
            ('buyTime', DESCENDING)
        ],
        indexDict=licColIndices, collection=licCol)
    _createIndex(
        name='licenseConsumerActivationTimeIndex',
        constraints=[
            ('consumer', ASCENDING),
            ('activationTime', DESCENDING)
        ],
        indexDict=licColIndices, collection=licCol)
    _createIndex(
        name='licenseConsumerActivationIpIndex',
        constraints=[
            ('consumer', ASCENDING),
            ('activationIp', DESCENDING)
        ],
        indexDict=licColIndices, collection=licCol)

def _initializeJWTCollection() -> None:
    """Initialize JWT collection for auth user."""
    # JWT collection
    # Current do nothing

def _createIndex(
    name: str, constraints: List[Tuple[str, int]],
    indexDict: Dict[str, Any], collection: Collection, **kwargs
) -> None:
    """Create index on specified collection.
     :param name: index name.
     :param constraints: index constraint list.
     :param indexDict: all already existed index dict retrieved from collection.index_information().
     :param collection: the collection instance.
    Additional parameters are defined in:
        https://pymongo.readthedocs.io/en/stable/api/pymongo/collection.html#pymongo.collection.Collection.create_index
    """
    if name in indexDict:
        return
    collection.create_index(
        constraints, name=name, background=GlobalConfig.DbCreateIndexInBackground,
        **kwargs)

def getUser(userId: str, password: str=None) -> Dict[str, str]:
    """Get user by user id and selected password as filter.
     :return: complete user data if found; None if not.
    """
    constraint = { '_id': userId }
    if password:
        constraint['password'] = password
    return db.db.user.find_one(constraint)

def constructErrorResponse(httpCode: int, code: int, msg: str = '') -> str:
    """Construct ErrorResult response string."""
    return make_response(jsonify({ 'code': code, 'msg': msg }), httpCode)
