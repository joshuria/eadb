# -*- coding: utf-8 -*-
"""ProductStatus model used in User model."""
from __future__ import annotations
from typing import Any, Dict
import mongoengine as me
from ..timefunction import now, ZeroDateTime


class ProductStatus(me.EmbeddedDocument):
    """Defines product status document used by User."""
    broker = me.StringField(required=True)
    eaId = me.StringField(required=True)
    mId = me.StringField(required=True)
    expireTime = me.DateTimeField(default=ZeroDateTime)

    @staticmethod
    def toDict(status: ProductStatus) -> Dict[str, Any]:
        """Convert status object to dict."""
        o = status.to_mongo()
        o['valid'] = status.expireTime <= now()
        return o
