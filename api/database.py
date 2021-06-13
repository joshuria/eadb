# -*- coding: utf-8 -*-
"""Defines global database instance."""
from __future__ import print_function
from flask.helpers import make_response
from flask.json import jsonify
from flask_mongoengine import MongoEngine
from mongoengine import NotUniqueError
from config import GlobalConfig
from model import User, Log, LogOperation


db = MongoEngine()

def initializeDb(app) -> None:
    """Initialize db instance."""
    db.init_app(app)
    _initDefaultUser()

def _initDefaultUser() -> None:
    admin = User(
        uid=GlobalConfig.DbDefaultAdmin,
        password='xyzzy',
        log=[Log(operation=LogOperation.CreateUser, ip='')])
    try:
        admin.save(force_insert=True)
    except NotUniqueError:
        # Already exist, do nothing
        pass

def constructErrorResponse(httpCode: int, code: int, msg: str = '') -> str:
    """Construct ErrorResult response string."""
    return make_response(jsonify({ 'code': code, 'msg': msg }), httpCode)
