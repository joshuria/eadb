# -*- coding: utf-8 -*-
"""Log model used in User model."""
from __future__ import annotations
import uuid
from typing import Any, Dict
import mongoengine as me
from ..timefunction import InfDateTime, ZeroDateTime, now


def _generateId() -> str:
    """Generate license ID implementation."""
    return str(uuid.uuid4())

class License(me.EmbeddedDocument):
    """Defines model of license collection used by User collection."""
    lid = me.StringField(primary_key=True, default=_generateId)
    broker = me.StringField(required=True)
    eaId = me.StringField(required=True)
    duration = me.IntField(default=30)
    owner = me.StringField(required=True)
    buyTime = me.DateTimeField(default=now)
    consumer = me.StringField(default='')
    activationTime = me.DateTimeField(default=InfDateTime)
    activationIp = me.StringField(default='')

    @staticmethod
    def generateId() -> str:
        """Generate global unique license ID."""
        return _generateId()

    @staticmethod
    def fromDict(dic: Dict[str, Any]) -> License:
        """Create License instance from dict which is returned from pymongo query."""
        dic['lid'] = dic['_id']
        del dic['_id']
        return License(**dic)
