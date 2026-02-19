import os
import jwt
import sys
import uuid
import sqlite3
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, render_template, jsonify, make_response, url_for, redirect

app = Flask(
    __name__
)
DB_PATH = 'database.db'
app.config['SECRET_KEY'] = 'rash'
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024

def get_logged_in_user():
    token = request.cookies.get("token")
    if not token:
        return None
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return data["username"]
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

class Brains:
    @staticmethod
    def get_hash(file_obj):
        h = hashlib.sha256()
        file_obj.seek(0)
        for chunk in iter(lambda: file_obj.read(4096), b""):
            h.update(chunk)
        file_obj.seek(0)
        return h.hexdigest()

    @staticmethod
    def register(username:str, file_obj:str):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, pdf) VALUES (?, ?)", (username, Brains.get_hash(file_obj)))
        conn.commit()
        conn.close()
        return True

    @staticmethod
    def get_user_hash(pdf_obj:str):
        pdf_hash = Brains.get_hash(pdf_obj)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE pdf=?", (pdf_hash,))
        user = cursor.fetchone()
        conn.close()
        return user

@app.route('/')
def index():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('register'))
    return render_template('index.html', username=user)

@app.route('/register', methods=['POST','GET'])
def register():
    if get_logged_in_user():
        return render_template('index.html')
    if request.method == 'GET':
        return render_template('register.html')
    
    username = request.form['username']
    pdf_file = request.files.get('filename')
    if not pdf_file:
        return render_template('register.html', error="No PDF uploaded.")
    
    if Brains.get_user_hash(pdf_file):
        return render_template('register.html', error="User already exists.")

    Brains.register(username, pdf_file)
    return render_template('login.html')

@app.route('/login', methods=['POST','GET'])
def login():
    if get_logged_in_user():
        return redirect(url_for('index'))

    if request.method == 'GET':
        return render_template('login.html')

    pdf_file = request.files.get('filename')
    if not pdf_file:
        return render_template('login.html', error="No PDF uploaded.")
    
    user = Brains.get_user_hash(pdf_file)
    username = user[0]
    if user:
        token = jwt.encode(
            {"username": username, "exp": datetime.utcnow() + timedelta(minutes=30)},
            app.config['SECRET_KEY'],
            algorithm="HS256"
        )
        resp = make_response(render_template('index.html', username=username))
        resp.set_cookie('token',token, httponly=True, secure=False, samesite='Strict')
        return resp
    return render_template('login.html', error="Invalid username or PDF")

if __name__ == '__main__':
    app.run(port=8080)