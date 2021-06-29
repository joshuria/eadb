# -*- coding: utf-8 -*-
"""API entry.
All used environment variables are listed in config.py.
"""
from datetime import datetime
import logging
from logging.config import dictConfig
from flask import Flask
from flask.json import JSONEncoder
from api.v1 import V1Api
from api.manager import JwtManager, Database, MailManager
from api.config import GlobalConfig
from api.timefunction import dateTimeToEpochMS


class CustomJSONEncoder(JSONEncoder):
    def default(self, obj):
        try:
            if isinstance(obj, datetime):
                #return obj.isoformat()
                return dateTimeToEpochMS(obj)
            iterable = iter(obj)
        except TypeError:
            pass
        else:
            return list(iterable)
        return JSONEncoder.default(self, obj)


def create_app(isTesting: bool=False):
    """Create flask main app."""
    # logger
    dictConfig({
        'version': 1,
        'formatters': {'default': {
            'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        }},
        'handlers': {'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
            'formatter': 'default'
        }},
        'root': {
            'level': 'INFO',
            'handlers': ['wsgi']
        }
    })
    # app
    app = Flask(__name__)
    # Create logger instance
    app.logger
    # Other settings
    app.json_encoder = CustomJSONEncoder
    app.config['MONGODB_SETTINGS'] = {
        'db': GlobalConfig.DbName + ('' if not isTesting else '-test'),
        'host': GlobalConfig.DbConnectionString,
        'tz_aware': True,
    }
    app.testing = isTesting
    app.config['JWT_SECRET_KEY'] = GlobalConfig.JwtSecret
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = GlobalConfig.JwtExpireTime
    app.config['MAIL_SERVER'] = GlobalConfig.MailServer
    app.config['MAIL_PORT'] = GlobalConfig.MailServerPort
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USERNAME'] = GlobalConfig.MailUsername
    app.config['MAIL_PASSWORD'] = GlobalConfig.MailPassword
    app.register_blueprint(V1Api, url_prefix='/api/v1')


    Database.initialize(app)
    JwtManager.initialize(app)
    MailManager.initialize(app)
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(
        debug=GlobalConfig.ServerDebug,
        host='0.0.0.0',
        port=GlobalConfig.ServerPort
    )
