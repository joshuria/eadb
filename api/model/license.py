# -*- coding: utf-8 -*-
"""Log model used in User model."""
import uuid
import mongoengine as me
from ..timefunction import ZeroDateTime, now


class License(me.EmbeddedDocument):
    """Defines model of license collection used by User collection."""
    lid = me.StringField(db_field='_id', primary_key=True)
    eaType = me.IntField(required=True)
    durationDay = me.IntField(db_field='duration', default=30)
    owner = me.StringField(required=True)
    buyTime = me.DateTimeField(default=now)
    consumer = me.StringField(default='')
    activationTime = me.DateTimeField(default=ZeroDateTime)
    activationIp = me.StringField(default='')

    @staticmethod
    def generateId() -> str:
        """Generate global unique license ID."""
        return str(uuid.uuid4())
