# models.py
# Standard library imports
# Third-party imports

from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func


class Note(db.Model): # table name is Note
    id = db.Column(db.Integer, primary_key=True) # Note.id is the primary key
    data = db.Column(db.String(10000)) # note string is a maximum of 10,000 characters
    date = db.Column(db.DateTime(timezone=True), default=func.now()) # keeps a datetime reference of when notes are created
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) # uses User tables User.id as the foreign key relationship

    
class User(db.Model, UserMixin): # table name is User
    id = db.Column(db.Integer, primary_key=True) # User.id is the primary key
    username = db.Column(db.String(150), unique=True) # username string maximum of 150 characters
    password = db.Column(db.String(150)) # password string maxmimum of 150 characters
    notes = db.relationship('Note') # declares relationship with Note table
