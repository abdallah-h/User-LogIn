from flask import render_template, url_for, flash, redirect, request, jsonify
from log import app, db, bcrypt, mail
from log.forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm
from log.models import User
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
import threading
import datetime
import os
from werkzeug.utils import secure_filename
from flask import copy_current_request_context

@app.route('/json/')
def json():
    users = db.session.query(User).all()
    return jsonify(users=[i.serialize for i in users])


@app.route("/register/", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created successfully. You can now log in', 'success')
        return redirect(url_for('account'))
    return render_template('register.html', title='Register', form=form)


@app.route("/", methods=['GET', 'POST'])
@app.route("/login/", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('account'))
        else:
            flash('Login Unsuccessful. Please check your email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/upload/", methods=['POST','GET'])
def upload():
    @copy_current_request_context
    def save_file(closeAfterWrite):
        print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " i am doing")
        f = request.files['file']
        basepath = os.path.dirname(__file__) 
        upload_path = os.path.join(basepath, '',secure_filename(f.filename)) 
        f.save(upload_path)
        closeAfterWrite()
        print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " write done")
    def passExit():
        pass
    if request.method == 'POST':
        f= request.files['file']
        normalExit = f.stream.close
        f.stream.close = passExit
        t = threading.Thread(target=save_file,args=(normalExit,))
        t.start()
        return redirect(url_for('upload'))
    return render_template('upload.html')


@app.route("/logout/")
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/account/")
@login_required
def account():
    return render_template('account.html', title='Account')


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='abdohfox18@gmail.com',
                  recipients=[user.email])
    msg.body = '''To reset your password, visit the following link:{}'''.format(url_for('reset_token', token=token, _external=True))
    mail.send(msg)


@app.route("/reset_password/", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('Further instructions have been sent to your e-mail address to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated. You can now log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)