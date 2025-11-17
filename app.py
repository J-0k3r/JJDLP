from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import Config

db = SQLAlchemy()
from models import *

# 初始化Flask应用
app = Flask(__name__)
app.config.from_object(Config)

# 初始化数据库
# db = SQLAlchemy(app)
db.init_app(app)
migrate = Migrate(app, db)

# 导入模型并初始化数据库
# from models import *
# init_db(db)

# 导入路由
# 注意：访问日志配置在 routes/main.py 中，因为Flask应用在那里创建
from routes.main import *

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
