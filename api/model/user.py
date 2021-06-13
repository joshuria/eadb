# -*- coding: utf-8 -*-
"""User model."""
from __future__ import annotations
from datetime import datetime
import mongoengine as me
from common import DefaultZeroDateTime
from config import GlobalConfig
from model import AuthSet, EAStatus, License, Log, Status


class User(me.DynamicDocument):
    """Defines User collection entity."""
    meta = {
        'collection': 'user',
        'index_background': GlobalConfig.DbCreateIndexInBackground,
        'indexes': [
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
    createTime = me.DateTimeField(default=datetime.utcnow())
    status = me.IntField(default=Status.Enabled, choices=Status.getAllStatus())
    lastLoginTime = me.DateTimeField(default=DefaultZeroDateTime)
    lastLoginIp = me.StringField(default='')
    availableLicenses = me.EmbeddedDocumentListField(License, db_field='licenses', default=list)
    eaStatus = me.EmbeddedDocumentListField(EAStatus, default=list)
    log = me.EmbeddedDocumentListField(Log, default=list)
    auth = me.EmbeddedDocumentListField(AuthSet, default=list)

    @staticmethod
    def getById(
        userId: str, keepLogCount: int=-32,
        excludePassword: bool=True, excludeFieldsForAuth: bool=True
    ) -> me.QuerySet:
        """Get User instance by uid (_id).
         :return: QuerySet instance of user
        """
        query = User.objects(uid=userId)
        if keepLogCount != 0:
            query = query.fields(slice__log=keepLogCount)
        else:
            query = query.exclude('log')
        if excludeFieldsForAuth:
            query = query.exclude('uid', 'availableLicenses', 'auth')
        if excludePassword:
            query = query.exclude('password')
        return query
