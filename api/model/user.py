# -*- coding: utf-8 -*-
"""User model."""
from __future__ import annotations
from typing import Tuple
import re
import mongoengine as me
from ..config import GlobalConfig
from ..timefunction import ZeroDateTime, now
from . import AuthSet, ProductStatus, License, Status


class User(me.DynamicDocument):
    """Defines User collection entity."""
    meta = {
        'collection': 'user',
        'index_background': GlobalConfig.DbCreateIndexInBackground,
        'indexes': [
            # Query if (lid, broker, eaId) can be activated
            # and all license ids by user's (broker, eaId)
            {
                'name': 'userLicensesBrokerEaId',
                'fields': ['license.broker', 'license.eaId'],
            },
            # Query who activates license by given lid
            # or query license info by Id
            {
                'name': 'userLicensesId',
                'fields': ['license.lid']
            },
            # Query productStatus by given (broker, eaId, mId)
            {
                'name': 'userProductStatusBrokerEaIdMtId',
                'fields': ['productStatus.broker',  'productStatus.eaId', 'productStatus.mId'],
            },
            # License TTL
            {
                'name': 'userLicenseTTL',
                'fields': ['license.activationTime'],
                'expireAfterSeconds': GlobalConfig.DbUserLicenseExpireDay * 24 * 60 * 60
            },
        ]
    }
    uid = me.StringField(db_field='_id', min_length=4, max_length=64, primary_key=True)
    createTime = me.DateTimeField(default=now)
    status = me.IntField(default=Status.Enabled, choices=Status.getAllStatus())
    lastLoginTime = me.DateTimeField(default=ZeroDateTime)
    lastLoginIp = me.StringField(default='')
    license = me.EmbeddedDocumentListField(License, default=list)
    productStatus = me.EmbeddedDocumentListField(ProductStatus, default=list)
    auth = me.EmbeddedDocumentListField(AuthSet, default=list)

    @staticmethod
    def verifyUserId(userId: str) -> bool:
        """Verify user id format.
         :note: currently format is email.
        """
        return re.match(r'[^@]+@[^@]+\.[^@]+', userId) is not None
