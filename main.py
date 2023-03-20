from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import StringField, PasswordField, SubmitField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired
from datetime import date
import os
from dotenv import load_dotenv

load_dotenv(".env")

now = date.today().strftime("%B %d, %Y")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
Bootstrap(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


class RegisterForm(FlaskForm):
    name = StringField("User Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class LoginUser(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password= PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class Users(UserMixin, db.Model):
    __tablename__ = "user_data"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    list_item = relationship("UserList", back_populates="author")
    whole_list = relationship("CompleteLists", back_populates="manager")


class UserList(UserMixin, db.Model):
    __tablename__ = 'each_list_item'
    id = db.Column(db.Integer, primary_key=True)
    list_item = db.Column(db.String, nullable=False)
    due_date = db.Column(db.String, nullable=False)
    auther_id = db.Column(db.Integer, db.ForeignKey('user_data.id'))
    author = relationship("Users", back_populates="list_item")


class CompleteLists(UserMixin, db.Model):
    __tablename__ = 'complete_lists'
    id = db.Column(db.Integer, primary_key=True)
    list = db.Column(db.String, nullable=False)
    auther_id = db.Column(db.Integer, db.ForeignKey('user_data.id'))
    manager = relationship("Users", back_populates="whole_list")


# with app.app_context():
#     db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginUser()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = Users.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('create_list'))
        else:
            flash("Invalid credentials")
    return render_template("login.html", form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if Users.query.filter_by(email=form.email.data).first():
            flash("You have already registered. Log in to continue.")
            return redirect(url_for('login'))
        else:
            new_user = Users(
                name=form.name.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data, "pbkdf2:sha256", 8)
            )
        db.session.add(new_user)
        db.session.commit()
        user = Users.query.filter_by(email=form.email.data).first()
        login_user(user)
        return redirect(url_for('create_list'))
    return render_template("login.html", form=form)


@app.route('/create_list', methods=['GET', 'POST'])
def create_list():
    list_items = UserList.query.filter_by(auther_id=current_user.id)
    done_items = CompleteLists.query.filter_by(auther_id=current_user.id)
    if request.method == "POST":
        task = request.form.get("task")
        due_date = request.form.get("due_date")
        if task:
            new_task = UserList(
                list_item=task,
                due_date=due_date,
                auther_id=current_user.id
            )
            db.session.add(new_task)
            db.session.commit()
        return redirect(url_for('create_list'))
    return render_template("creat.html", items=list_items, current_user=current_user, done=done_items, date=now)


@app.route('/delete<int:list_id>')
def delete(list_id):
    item = UserList.query.filter_by(id=list_id).first()
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('create_list'))


@app.route('/done<int:list_id>')
def done(list_id):
    item = UserList.query.filter_by(id=list_id).first()
    done_task = CompleteLists(
        list=item.list_item,
        auther_id=current_user.id
    )
    db.session.add(done_task)
    db.session.commit()
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('create_list'))


@app.route('/del_frm_db<int:list_id>')
def del_frm_db(list_id):
    item = CompleteLists.query.filter_by(id=list_id).first()
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('create_list'))


@app.route('/create_new')
def create_new():
    items = CompleteLists.query.filter_by(auther_id=current_user.id)
    for item in items:
        db.session.delete(item)
        db.session.commit()
    done_items = UserList.query.filter_by(auther_id=current_user.id)
    for item in done_items:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('create_list'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)