# -*- coding: utf-8 -*-
"""User model."""
from __future__ import annotations
from typing import Tuple
import re
import mongoengine as me
from ..config import GlobalConfig
from ..timefunction import ZeroDateTime, now
from . import AuthSet, EAStatus, License, Log, Status


class User(me.DynamicDocument):
    """Defines User collection entity."""
    meta = {
        'collection': 'user',
        'index_background': GlobalConfig.DbCreateIndexInBackground,
        'indexes': [
            {
                'name': 'userLicenseId',
                'fields': ['availableLicenses.lid'],
            },
            {
                'name': 'userLicenseOwnerBuyTimeIndex',
                'fields': ['availableLicenses.owner',  '-availableLicenses.buyTime'],
            },
            {
                'name': 'userLicenseConsumerActivationTimeIndex',
                'fields': ['availableLicenses.consumer',  '-availableLicenses.activationTime'],
            },
            {
                'name': 'userLogTimestampOperationIndex',
                'fields': ['log.timestamp', 'log.operation'],
            },
            {
                'name': 'userLogTimestampTTLIndex',
                'fields': ['log.timestamp'],
                'expireAfterSeconds': GlobalConfig.DbUserLogExpireDay * 24 * 60 * 60
            }
        ]
    }
    uid = me.StringField(db_field='_id', min_length=4, max_length=32, primary_key=True)
    password = me.StringField(required=True)
    createTime = me.DateTimeField(default=now)
    status = me.IntField(default=Status.Enabled, choices=Status.getAllStatus())
    lastLoginTime = me.DateTimeField(default=ZeroDateTime)
    lastLoginIp = me.StringField(default='')
    availableLicenses = me.EmbeddedDocumentListField(License, db_field='licenses', default=list)
    eaStatus = me.EmbeddedDocumentListField(EAStatus, default=list)
    log = me.EmbeddedDocumentListField(Log, default=list)
    auth = me.EmbeddedDocumentListField(AuthSet, default=list)

    @staticmethod
    def verifyUserId(userId: str) -> bool:
        """Verify user id format.
         :note: currently format is email.
        """
        return re.match(r'[^@]+@[^@]+\.[^@]+', userId) is not None

    @staticmethod
    def getById(
        userId: str, keepLogCount: int=-32,
        excludeList: Tuple[str] = ('uid', 'availableLicenses', 'auth', 'password')
    ) -> me.QuerySet:
        """Get User instance by uid (_id).
         :return: QuerySet instance of user
        """
        query = User.objects(uid=userId)
        if keepLogCount != 0:
            query = query.fields(slice__log=keepLogCount)
        else:
            query = query.exclude('log')
        if len(excludeList) > 0:
            query = query.exclude(*excludeList)
        return query
