import io,os
from app import app
import sqlite3 as sql
from flask import jsonify,flash,request,Blueprint,g,send_from_directory,redirect,url_for,render_template,session,abort
from werkzeug import generate_password_hash, check_password_hash,secure_filename
from flask_restful import Api,Resource,fields
from passlib.hash import pbkdf2_sha256 as sha256
from marshmallow import Schema,fields as ma_fields,post_load
from flask_jwt import JWT
from werkzeug.security import safe_str_cmp
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from flask_httpauth import HTTPBasicAuth
from flask_bcrypt import Bcrypt
import jwt
import datetime
from flask_simplelogin import SimpleLogin, get_username, login_required
import os
from flask import Flask

app=Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'



bcrypt = Bcrypt()

auth = HTTPBasicAuth()


global token


import unittest

def encode_auth_token(user_id):
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            app.config.get('SECRET_KEY'),
            algorithm='HS256'
        )
    except Exception as e:
        return e




    
def decode_auth_token(auth_token):
    try:
        payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'


def test_decode_auth_token(self):
    user = User(
        email='test@test.com',
        password='test'
    )
    db.session.add(user)
    db.session.commit()
    auth_token = user.encode_auth_token(user.id)
    self.assertTrue(isinstance(auth_token, bytes))
    self.assertTrue(User.decode_auth_token(auth_token) == 1)

@app.route('/')
def root():
    print("hqeandkd")
    return render_template('index.html')

@app.route('/signup',methods=['POST'])
def add_user():
    try:
        _json = request.json
        _name = _json['name']
        _email = _json['email']
        _password = _json['password']
        if _name and _email and _password and request.method == 'POST':            
            _hashed_password = bcrypt.generate_password_hash(_password, app.config.get('BCRYPT_LOG_ROUNDS')).decode()
            con = sql.connect("database.db")
            cur = con.cursor()
            cur.execute("INSERT INTO users (user_name,user_email,user_password) VALUES (?,?,?)",(_name,_email,_hashed_password))
            con.commit()
            resp = jsonify('USER REGISTERED')
            resp.status_code = 200
            path = "127.0.0.1:5000/login"
            return jsonify({'msg' : 'SIGNED UP', 'path' : path}) 
        else:
            path = "127.0.0.1:5000/signup"
            return jsonify({'msg1' : 'NOT SIGNED UP', 'path' : path})

    except Exception as e:
        print(e)
        con.rollback()

    finally:
        cur.close()
        con.close()

@app.route('/login',methods=['POST'])
def login():
    try:
        _json =  request.json
        _email = _json['email']
        _password = _json['password']
        print(_email)
        con = sql.connect("database.db")
        cur = con.cursor()
        cur.execute("SELECT  * FROM users WHERE user_email = ?",(_email,))
        data = cur.fetchone()
        if data is None:
            return jsonify('USER DOES NOT EXIST')
        else :
            if(bcrypt.check_password_hash(data[3],_password)):
                global token
                token = encode_auth_token(_email)
                print(token)
                print(decode_auth_token(token))
                session['loggedin']=True
                print("loggedin")
                email = decode_auth_token(token)
                #return redirect(url_for('teachers_team'))
                return jsonify({'msg' : 'LOGGED IN'})
            else:
                return jsonify({'msg1' : 'credentials are wrong'})
                            
    except Exception as e:
        print(e)
        con.rollback()
        return(jsonify(e))

    finally:
        cur.close()
        con.close()

@app.route('/logout')
def logout():
    session['loggedin']=False
    return jsonify('LOGGED OUT')

@app.route('/profile')
def teachers_team():
    if session.get('loggedin'):
        try:
            email = decode_auth_token(token)
            print(email)
            con = sql.connect("database2.db")
            cur = con.cursor()
            cur.execute("SELECT  * FROM teacher WHERE teacher_email = ?",(email,))
            data = cur.fetchone()
            cur1 = con.cursor()
            cur1 = con.cursor()
            cur1.execute("SELECT * FROM teacher WHERE teacher_email = ?",(email,))
            data1 = cur1.fetchall()
            print(data1)
            print(data)
            resp = jsonify(data1)
            resp.status_code = 200
            cur.close()
            cur1.close()
            con.close()
            return resp

        except Exception as e:
            print(e)

    else:
        return(jsonify("PLEASE LOG IN FIRST"))

@app.route('/login/profile/add',methods=['POST'])
def addafterlogin():
    if session.get('loggedin'):
        try:
            _json =  request.json
            team_name = _json['team_name']
            student1 = _json['student1']
            student2 = _json['student2']
            student3 = _json['student3']
            email=decode_auth_token(token)
            print(email)
            con = sql.connect("database.db")
            cur = con.cursor()
            cur.execute("SELECT  * FROM users WHERE user_email = ?",(email,))
            data = cur.fetchone()
            name=data[1]
            cur.close()
            con.close()
            con1 = sql.connect("database2.db")
            cur1 = con1.cursor()
            cur1.execute("INSERT INTO teacher (teacher_name,teacher_email,team_name,student1,student2,student3) VALUES (?,?,?,?,?,?)",(name,email,team_name,student1,student2,student3))
            con1.commit()
            cur1.execute("SELECT  * FROM teacher WHERE teacher_email = ?",(email,))
            data=cur1.fetchall()
            resp = jsonify(data)
            print(data)
            return resp
            cur1.close()
            con1.close()

        except Exception as e:
            print(e)
            return(jsonify(e))

    else:
        return jsonify("PLEASE LOG IN")

@app.route('/login/profile/delete',methods=['POST'])
def deleteafterlogin():
    if session.get('loggedin'):
        try:
            _json = request.json
            team_name = _json['team_name']
            email = decode_auth_token(token)
            print(email)
            con1 = sql.connect("database2.db")
            cur1 = con1.cursor()
            cur1.execute("DELETE FROM teacher WHERE teacher_email=? AND team_name=?",(email,team_name,))
            con1.commit()
            cur1.execute("SELECT  * FROM teacher WHERE teacher_email = ?",(email,))
            data=cur1.fetchall()
            resp = jsonify(data)
            print(data)
            return resp
            cur1.close()
            con1.close()

        except Exception as e:
            print(e)
            return(jsonify(e))

    else:
        return jsonify("PLEASE LOG IN")

@app.route('/users')
def users():
    try:
        con = sql.connect("database.db")
        cur = con.cursor()
        cur.execute("SELECT * FROM users")
        rows = cur.fetchall()
        resp = jsonify(rows)
        resp.status_code = 200
        return resp
    except Exception as e:
        print(e)

    finally:
        cur.close()
        con.close()

@app.route('/user/<_name>')
def user(_name):
    try:
        con = sql.connect("database.db")
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE user_email = ?",(_name,))
        row = cur.fetchone()
        print (row)
        resp = jsonify(row)
        resp.status_code = 200
        return resp
    except Exception as e:
        print(e)
    finally:
        cur.close()
        con.close()

@app.route('/update',methods=['POST'])
def update_user():
    try:
        _json = request.json
        _pname = _json['pname']
        _name = _json['name']
        _email = _json['email']
        _password = _json['password']
        if _name and _email and _password and request.method == 'POST':
            _hashed_password = pwd_context.encrypt(_password)
            con = sql.connect("database.db")
            cur = con.cursor()
            print(_name)
            cur.execute("UPDATE users SET user_name = ?, user_email = ?, user_password = ? WHERE user_name = ?",(_name,_email,_hashed_password,_pname,))
            con.commit()
            resp = jsonify('User updated successfully')
            resp.status_code = 200
            return resp
        else:
            return not_found()
    except Exception as e:
        print(e)

    finally:
        cur.close()
        con.close()


@app.route('/delete/<_name>')
def delete_user(_name):
    try:
        con = sql.connect("database.db")
        cur = con.cursor()
        cur.execute("DELETE FROM users WHERE user_name = ?",(_name,))
        con.commit()
        resp = jsonify('User deleted successfully')
        resp.status_code = 200
        return resp
    except Exception as e:
        print(e)
    finally:
        cur.close()
        con.close()

@app.errorhandler(404)
def not_found(error=None):
    message ={
        'status':404,
        'message':'Not Found: ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 404

    return resp

UPLOAD_FOLDER = 'uploads/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/upload/<team_name>', methods=['GET', 'POST'])
def upload_file(team_name):
    
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            s2 = '.pdf'
            filename = team_name + s2
            print(filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return render_template(('upload.html'),team_name=team_name)

@app.route('/profile/upload')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],filename)

if __name__ == "__main__":
    app.run(debug=True)
    unittest.main()
    app.secret_key = os.urandom(10)
