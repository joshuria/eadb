# -*- coding: utf-8 -*-
"""API entry.
All used environment variables are listed in config.py.
"""
from flask import Flask
from v1 import V1Api
from jwtmanager import initializeJwt
from database import initializeDb
from config import GlobalConfig

app = Flask(__name__)
#app.config['MONGO_URI'] = GlobalConfig.DbConnectionString
app.config['MONGODB_SETTINGS'] = {
    'db': GlobalConfig.DbName,
    'host': GlobalConfig.DbConnectionString
}
app.config['JWT_SECRET_KEY'] = GlobalConfig.JwtSecret
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = GlobalConfig.JwtExpireTime
app.register_blueprint(V1Api, url_prefix='/api/v1')

initializeDb(app)
initializeJwt(app)

if __name__ == '__main__':
    app.run(
        debug=GlobalConfig.ServerDebug,
        host='0.0.0.0',
        port=GlobalConfig.ServerPort
    )
