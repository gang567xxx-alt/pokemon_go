from flask import Blueprint, render_template, request, url_for, redirect, flash
from pokemon.extensions import db, bcrypt
from pokemon.models import User
from flask_login import login_user, logout_user, current_user, login_required

users_bp = Blueprint('users', __name__, template_folder='templates')

@users_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        query = db.select(User).where(User.username == username)
        user = db.session.scalar(query)
        if user:
            flash('Username is already exists!', 'warning')
            return redirect(url_for('users.register'))

        query = db.select(User).where(User.email == email)
        user = db.session.scalar(query)
        if user:
            flash('Email is already exists!', 'warning')
            return redirect(url_for('users.register'))

        if password == confirm_password:
            pwd_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, email=email, password=pwd_hash)

            db.session.add(user)
            db.session.commit()
            flash('Register sucessful!', 'success')
            return redirect(url_for('users.login'))
        else:
            flash('Password not match!', 'warning')
            return redirect(url_for('users.register'))

    return render_template('users/register.html', title='Register Page')


@users_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        query = db.select(User).where(User.username == username)
        user = db.session.scalar(query)

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('users.index'))
        else:
            flash('Username or password is incorrect!', 'warning')
            return redirect(url_for('users.login'))

    return render_template('users/login.html', title='Login Page')


@users_bp.route('/')
@login_required
def index():
    return render_template('users/index.html', title='User Page')


@users_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('core.index'))


@users_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user
    if request.method == 'POST':
        firstname = (request.form.get('firstname') or '').strip()
        lastname = (request.form.get('lastname') or '').strip()

        if firstname and lastname:
            user.firstname = firstname
            user.lastname = lastname

            db.session.add(user)
            db.session.commit()
            flash('Update profile successful', 'success')
            return redirect(url_for('users.profile'))
        else:
            flash('Please fill in both firstname and lastname', 'warning')
            return redirect(url_for('users.profile'))

    return render_template('users/profile.html', title='Profile Page', user=user)


@users_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # เช็ครหัสผ่านปัจจุบัน
        if not bcrypt.check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect!', 'danger')
            return redirect(url_for('users.change_password'))

        # เช็ครหัสใหม่ตรงกัน
        if new_password != confirm_password:
            flash('New password does not match!', 'warning')
            return redirect(url_for('users.change_password'))

        # (กันพลาด) รหัสใหม่ห้ามว่าง
        if not new_password:
            flash('New password cannot be empty!', 'warning')
            return redirect(url_for('users.change_password'))

        # อัปเดตรหัสผ่าน
        hashed = bcrypt.generate_password_hash(new_password).decode('utf-8')
        current_user.password = hashed
        db.session.commit()

        flash('Password changed successfully!', 'success')
        return redirect(url_for('users.profile'))

    return render_template('users/change_password.html', title='Change Password')