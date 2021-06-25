# -*- coding: utf-8 -*-
"""Database manager."""
from flask_mongoengine import MongoEngine
from mongoengine import NotUniqueError
from ..config import GlobalConfig
from ..model import User, Log, LogOperation


class Database:
    """Singleton for mongoengine ORM manager."""
    db = MongoEngine()

    @staticmethod
    def initialize(app) -> None:
        """Initialize manager with flask app intance."""
        Database.db.init_app(app)

        # Create default admin user
        admin = User(uid=GlobalConfig.DbDefaultAdmin)
        try:
            admin.save(force_insert=True)
        except NotUniqueError:
            # Already exist, do nothing
            pass
