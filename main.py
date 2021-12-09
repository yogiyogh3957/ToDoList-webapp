from flask import Flask, render_template, redirect, url_for, flash, g, request, abort
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
from forms import CreateRegisterForm, LoginForm
from functools import wraps
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = "3957"
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", 'sqlite:///testv2.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#login
login_manager = LoginManager()
login_manager.init_app(app)

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.id :
            # return redirect(url_for('login'))
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    posts = relationship("BlogPost", back_populates="author")

    def __repr__(self):
        return f'<Book {self.id}>'

class BlogPost(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    notes = db.Column(db.String(250), unique=False, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    author = relationship("User", back_populates="posts")

##db.create_all()

notelist = []

@app.route('/logout')
def logout():
    global notelist
    notelist = []
    logout_user()
    return redirect(url_for('login'))

@app.route('/login', methods=["GET", "POST"])
def login():
    global notelist
    print(notelist)
    form = LoginForm()
    if form.validate_on_submit():

        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first() #ambil email di database dengan email yang dimasukan di form

        if not user :
            flash("Invalid Email or Password")
            return redirect(url_for('login'))
        #utk password HASHED
        if not check_password_hash(user.password, password):
            flash("Invalid Email or Password")
            return redirect(url_for('login'))
        else :
            login_user(user)
            for data in notelist:
                new_notes = BlogPost(
                    notes=data,
                    author=current_user
                )
                db.session.add(new_notes)
            db.session.commit()
            notelist.clear()
            return render_template('index.html', notelist=notelist)
    return render_template("login.html", form=form)

@app.route('/dashboard/<int:note_id>', methods=["GET", "POST"])
def dashboard(note_id):
    print(f"current_user_id = {current_user.id}")
    global notelist
    if not current_user.is_authenticated:
        try:
            return abort(403)
        except AttributeError :
            return abort(403)

    if current_user.is_authenticated:
        if current_user.id == note_id :
            user_notes = BlogPost.query.filter_by(author_id=note_id).all()
            if request.method == 'POST':
                if request.form['submit_button'] == '2':
                    print("db sv notes")
                    text = request.form['text']
                    new_notes = BlogPost(
                        notes=text,
                        author=current_user
                    )
                    db.session.add(new_notes)
                    db.session.commit()
                    return redirect(url_for("dashboard", note_id=current_user.id, user_notes=user_notes))

            return render_template('dashboard.html', note_id=current_user.id, user_notes=user_notes)
        else :
            return abort(403)


@app.route("/delete/<int:note_id>")
def delete_post(note_id):
    user_notes = BlogPost.query.filter_by(author_id=note_id).all()
    post_to_delete = BlogPost.query.get(note_id)
    print(post_to_delete)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("dashboard", note_id=current_user.id, user_notes=user_notes))

@app.route('/', methods=["GET", "POST"])
def home():
    global notelist
    if request.method == 'POST':

        if request.form['submit_button'] == '1':
            global notelist
            print("add notes")
            text = request.form['text']
            notelist.append(text)
            print(f"{notelist}")
            time.sleep(1)
            return redirect(url_for("home", notelist=notelist))

        if request.form['submit_button'] == '2':
            print("register/saves notes")
            if not current_user.is_authenticated:
                return redirect(url_for("register"))
            else:
                pass

        if request.form['submit_button'] == '3':
            notelist.clear()
            return redirect(url_for("home", notelist=notelist))

    return render_template('index.html', notelist=notelist)


@app.route('/register', methods=["GET", "POST"])
def register():
    global notelist
    print(notelist)
    form = CreateRegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data  # password tanpa hash
        password_hash_salt = generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)
        user_entry = User(email=email, password=password_hash_salt, name=name)

        if User.query.filter_by(email=email).first():
            flash("Email Already Registered, please login!")
            return redirect(url_for('login'))
        else:
            db.session.add(user_entry)
            db.session.commit()
            flash("Register Complete! Please Login!")
            return redirect(url_for('login'))
    return render_template('register.html', form=form)


#testgithub2

if __name__=="__main__":
    app.run(host=os.getenv('IP', '0.0.0.0'),
            port=int(os.getenv('PORT', 8935)), debug=True)