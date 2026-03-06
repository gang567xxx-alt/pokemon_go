import os
from flask import Flask
from pokemon.extensions import db, login_manager, bcrypt
from pokemon.models import User, Pokemon, Type
from pokemon.core.routes import core_bp
from pokemon.users.routes import users_bp
from pokemon.pokemons.routes import pokemons_bp

def create_app():
    app = Flask(__name__)

    # ✅ fallback ถ้าไม่ได้ตั้ง env
    db_url = os.environ.get("DATABASE_URL") or "sqlite:///app.db"
    secret = os.environ.get("SECRET_KEY") or "dev-secret-key"

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SECRET_KEY"] = secret
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "users.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"

    app.register_blueprint(core_bp, url_prefix="/")
    app.register_blueprint(users_bp, url_prefix="/users")
    app.register_blueprint(pokemons_bp, url_prefix="/pokemons")

    with app.app_context():
        db.create_all()

    return app
