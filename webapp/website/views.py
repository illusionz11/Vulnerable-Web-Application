# views.py Handles WHAT!!!!
# Standard library imports
# Third-party imports

from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from .models import Note
from . import db
import json

views = Blueprint('views', __name__) # defining blueprint

@views.route('/', methods=['GET', 'POST']) # route pointing to / page
def home():
    return render_template("home.html", user=current_user)

@views.route('/intro', methods=['GET', 'POST']) # route pointing to intro page
@login_required # put back in login_required
def intro():
    return render_template("intro.html", user=current_user)


@views.route('/notes', methods=['GET', 'POST']) # route pointing to notes page
# removed @login_required might stop the IDOR vuln
def notes():
    if request.method == 'POST': 
        note = request.form.get('note') # takes user input for a note

        if len(note) < 1:
            flash('Note is too short!', category='error') # filters note
        else:
            # states new note in Note table and links to user_id
            new_note = Note(data=note, user_id=current_user.id) 
            db.session.add(new_note)
            db.session.commit() # inserts note into database
            flash('Note added!', category='success')
    return render_template("notes.html", user=current_user)


@views.route('/delete-note', methods=['POST']) # route pointing to delete-note page
def delete_note():  
    note = json.loads(request.data) # this function expects a JSON from the INDEX.js file 
    noteId = note['noteId']
    note = Note.query.get(noteId) # queries Note table for note with corresponding id

    if note:
        if note.user_id == current_user.id: # use relationship connection if note with corresponding user.id = current users user.id
            db.session.delete(note) 
            db.session.commit() # deletes note
    return jsonify({})
