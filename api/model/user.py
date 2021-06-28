# -*- coding: utf-8 -*-
"""User model."""
from __future__ import annotations
import re
import mongoengine as me
from ..config import GlobalConfig
from ..timefunction import now
from . import AuthSet, ProductStatus, Status


class User(me.DynamicDocument):
    """Defines User collection entity."""
    meta = {
        'collection': 'user',
        'index_background': GlobalConfig.DbCreateIndexInBackground,
        'indexes': [
            # Query productStatus by given (broker, eaId, mId)
            {
                'name': 'userProductStatusBrokerEaIdMtId',
                'fields': ['productStatus.broker',  'productStatus.eaId', 'productStatus.mId'],
            },
        ]
    }
    uid = me.StringField(db_field='_id', min_length=4, max_length=64, primary_key=True)
    createTime = me.DateTimeField(default=now)
    status = me.IntField(default=Status.Enabled, choices=Status.getAllStatus())
    lastLoginTime = me.DateTimeField(default=now)
    lastLoginIp = me.StringField(default='')
    productStatus = me.EmbeddedDocumentListField(ProductStatus, default=list)
    auth = me.EmbeddedDocumentListField(AuthSet, default=list)

    @staticmethod
    def verifyUserId(userId: str) -> bool:
        """Verify user id format.
         :note: currently format is email.
        """
        return re.match(r'[^@]+@[^@]+\.[^@]+', userId) is not None
