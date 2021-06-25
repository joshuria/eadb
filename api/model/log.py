# -*- coding: utf-8 -*-
"""Log model used in User model."""
import mongoengine as me
from ..timefunction import now
from ..config import GlobalConfig


class Log(me.Document):
    """Defines Log document used by User."""
    meta = {
        'collection': 'log',
        'index_background': GlobalConfig.DbCreateIndexInBackground,
        'indexes': [
            # Query log in time range by given timestamp, its also a TTL index
            {
                'name': 'logTTL',
                'fields': ['-timestamp'],
                'expireAfterSeconds': GlobalConfig.DbUserLogExpireDay * 24 * 60 * 60
            },
            # Query user log
            {
                'name': 'logUserTime',
                'fields': ['user', '-timestamp']
            },
        ]
    }
    timestamp = me.DateTimeField(default=now)
    user  = me.StringField(required=True)
    operation = me.IntField(required=True)
    ip = me.StringField(required=True)
    message = me.StringField(default='')

class LogOperation():
    """Defines tracked operations in log."""
    Login = 0x0
    DeleteUser = 0x10
    ModifyUser = 0x11
    LicenseBuy = 0x20
    LicenseActivate = 0x21
