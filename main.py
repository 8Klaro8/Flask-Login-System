import json
from http import HTTPStatus
from os import abort

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, Response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
name_to_display = ''

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()

'''Setting up login manager'''
login_manager = LoginManager()
login_manager.init_app(app)

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        '''Uses hash method to hash the password and return its value'''
        hashed_password = has_password(password)

        '''Check if the entered email already exists in the database'''
        all_user = User.query.all()
        for user in all_user:
            if email == user.email:
                flash('This email already exists in the system', 'info')
                return redirect(url_for('register'))

                '''Render page method'''
                # email_exists = 'This email already added to our system.'
                # return render_template('register.html', email_exists=email_exists)

        new_user = User(name=name,
                        email=email,
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('secrets'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # TODO dont show login and or register page when logged in
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    all_user = User.query.all()
    email = request.form.get('email')
    password = request.form.get('password')


    '''Hidden input field in login.html. 
    It is identifying if the form on login.html was submitted'''
    if request.form.get("building") == "casinos":
        for user in all_user:
            if user.email == email:
                '''Checks if the entered email and hashed password are correct'''
                if check_hashed_password(pwhash=user.password, password=password):
                    login_user(user)
                    logged_in_message = 'You are logged in!'
                    # flash(u'Login successful!', 'info')
                    return redirect(url_for('secrets'))

                    '''This is without flash message. Renders page with extra message if conditions are met'''
                    # return render_template("login.html", logged_in_message=logged_in_message)

                elif not check_hashed_password(pwhash=user.password, password=password):
                    flash('This password is incorrect', 'error')
                    return redirect(url_for('login'))

                    '''This is without flash message. Renders page with extra message if conditions are met'''
                    # invalid_username_password = 'Password or username is invalid!'
                    # return render_template("login.html", invalid_username_password=invalid_username_password)

        else:
            flash('This email does not exist', 'error')
            return redirect(url_for('login'))


    return render_template("login.html")

@login_required
@app.route('/secrets', methods=['POST', 'GET'])
def secrets():
    '''If the user is authenticated - loged in - then we grant access to secret.html
    with the downloadable file'''
    if current_user.is_authenticated:
        current_user_name = current_user.name
        return render_template('secrets.html', current_user_name=current_user_name)
    else:
        '''If the user is not loged in, then we render secret.html with a different message
        and withut the downloadable file'''
        guest = 'guest'
        return render_template('secrets.html', guest=guest)
    '''Get current user who is logged in and pass its name to secrets.html'''



@app.route('/logout')
@login_required
def logout():
    logout_user()
    logged_out_user = 'You are logged out!'
    return render_template('index.html', logged_out_user=logged_out_user)

@login_required
@app.route('/download/<path:filename>', methods=['GET','POST'])
def download(filename):
    '''This was an example on the Flask Doc. I repalced -
    app.config['UPLOAD_FOLDER'] - with the path of the file'''
    return send_from_directory('static/files/',
                               filename, as_attachment=True)

def has_password(password):
    return generate_password_hash(password=password,
                           method='pbkdf2:sha256',
                           salt_length=8)
def check_hashed_password(pwhash, password):
    return check_password_hash(pwhash=pwhash, password=password)

'''Loads the user - currently not used'''
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)



if __name__ == "__main__":
    app.run(debug=True)
