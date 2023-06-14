from flask import Blueprint, render_template, request, flash, redirect, url_for

from . import db
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET','POST'])
def login():
    data = request.form
    if request.method == 'POST':
        email = request.form.get('email')
        passsword = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, passsword):
                flash("Loged In Successfully!", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash("Incorrect Password, Try Again.", category='error')
        else:
            flash("Email Does Not Exist.", category="error")
    return render_template('login.html', user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email Already Exist", category='error')
        elif len(email) < 4:
            flash("Email Must Be Greater Then 4 Characters", category='error')
        elif len(first_name) < 2:
            flash("First Name Must Be Greater Then 2 Characters", category='error')
        elif password1 != password2:
            flash("Passwords Don\'t Match", category='error')
        elif len(password1) < 2:
            flash("Password Must Be More Then 2 Characters", category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash("Account Created", category='success')
            login_user(user, remember=True)
            return redirect(url_for('views.home'))

    data = request.form
    print(data)


    return render_template('sign_up.html', user=current_user)

