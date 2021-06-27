# -*- coding: utf-8 -*-
"""Log model used in User model."""
from __future__ import annotations
import uuid
from typing import Any, Dict
import mongoengine as me
from ..timefunction import InfDateTime, now
from ..config import GlobalConfig


def _generateId() -> str:
    """Generate license ID implementation."""
    return str(uuid.uuid4())

class License(me.Document):
    """Defines model of license collection used by User collection."""
    meta = {
        'collection': 'license',
        'index_background': GlobalConfig.DbCreateIndexInBackground,
        'indexes': [
            # License TTL
            {
                'name': 'licenseTTL',
                'fields': ['activationTime'],
                'expireAfterSeconds': GlobalConfig.DbUserLicenseExpireDay * 24 * 60 * 60
            },
            # Query if (lid, broker, eaId) can be activated
            # and all license ids by user's (broker, eaId)
            {
                'name': 'licensesBrokerEaId',
                'fields': ['broker', 'eaId'],
            },
            # Query who owns license
            {
                'name': 'licensesOwner',
                'fields': ['owner', 'buyTime']
            },
            # Query who activates license
            {
                'name': 'licensesConsumer',
                'fields': ['consumer']
            },
        ]
    }
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
