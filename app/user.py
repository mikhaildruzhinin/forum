import functools
from flask import Blueprint
from flask import flash
from flask import g
from flask import redirect
from flask import request
from flask import session
from flask import url_for
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from app.db import get_db

bp = Blueprint('user', __name__, url_prefix='/user')


@bp.route('/create', methods=('GET','POST'))
def create_user():
    if request.method == 'POST':
        content = request.get_json()
        try:
            login = content['login']
        except KeyError:
            return {'message': f'Login is required'}, 401
        try:
            password = content['password']
        except KeyError:
            return {'message': f'Password is required'}, 401
        db = get_db()

        if db.execute(
            'SELECT id FROM user WHERE login = ?', (login,)
        ).fetchone() is not None:
            return {'message': f'User {login} already exists'}, 401
        db.execute(
            'INSERT INTO user (login, password) VALUES (?, ?)',
            (login, generate_password_hash(password))
        )
        db.commit()
        return {'message': 'Created successfully'}, 201
    return 'create user'


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        content = request.get_json()
        try:
            login = content['login']
        except KeyError:
            return {'message': f'Login is required'}, 401
        try:
            password = content['password']
        except KeyError:
            return {'message': f'Password is required'}, 401
        db = get_db()
        user = db.execute(
            'SELECT * FROM user WHERE login = ?', (login,)
        ).fetchone()

        if user is None:
            return {'message': f'Incorrect login'}, 401
        elif not check_password_hash(user['password'], password):
            return {'message': f'Incorrect password'}, 401

        session.clear()
        session['user_id'] = user['id']
        return {'message': 'Logged in successfully'}, 200
    return 'log in'


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


@bp.route('/logout', methods=('GET','POST'))
def logout():
    session.clear()
    return {'message': 'Logged out successfully'}, 200


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login')) # проверить, правильно ли работает

        return view(**kwargs)

    return wrapped_view()
