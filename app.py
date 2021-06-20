# -*- coding: utf-8 -*-
"""API entry.
All used environment variables are listed in config.py.
"""
from datetime import datetime
from flask import Flask
from flask.json import JSONEncoder
from api.v1 import V1Api
from api.jwtmanager import initializeJwt
from api.database import initializeDb
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
    app = Flask(__name__)
    app.json_encoder = CustomJSONEncoder
    app.config['MONGODB_SETTINGS'] = {
        'db': GlobalConfig.DbName + ('' if not isTesting else '-test'),
        'host': GlobalConfig.DbConnectionString
    }
    app.testing = isTesting
    app.config['JWT_SECRET_KEY'] = GlobalConfig.JwtSecret
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = GlobalConfig.JwtExpireTime
    app.register_blueprint(V1Api, url_prefix='/api/v1')

    initializeDb(app)
    initializeJwt(app)
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(
        debug=GlobalConfig.ServerDebug,
        host='0.0.0.0',
        port=GlobalConfig.ServerPort
    )
