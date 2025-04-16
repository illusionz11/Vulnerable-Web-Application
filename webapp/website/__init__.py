# Standard library imports
# Third-party imports

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect


# global variables
db = SQLAlchemy() # database uses SQLAlchemy
csrf = CSRFProtect() # enables CSRF protection


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs' # defines secret key
    app.config['UPLOAD_FOLDER'] = 'static/uploads' # defines upload folder location
    app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'} # defines allowed extensions
    app.config['MAX_FILE_SIZE'] = 100000 # defines max file size of 100KB
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{"database.db"}' # defines database name
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
    app.config['WTF_CSRF_ENABLED'] = False  # disables CSRF globally
    db.init_app(app) # binds database to flask app
    csrf.init_app(app)  # enables csrf protection for forms

    from .views import views
    from .auth import auth
    from .exploits import exploits

    #registers each blueprint
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(exploits, url_prefix='/')

    # imports User and Note from models db
    from .models import User, Note
    create_database(app)

    # manages user sessions 
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login' # redirects users to login page who are unauthorised
    login_manager.init_app(app)

    # function to load users
    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))
    return app

# checks if database exists if not it creates one
def create_database(app):
    with app.app_context():
        if not path.exists('website/' + 'database.db'):
            db.create_all()
            print('Created Database!')
