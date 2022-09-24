from flask import request, current_app
import jwt

from implemented import user_service


def auth_required(func):
    def wrapper(*args, **kwargs):
        token = request.headers.environ.get('HTTP_AUTHORIZATION').replace('Beaver ', '')

        if not token:
            return "Токен не пришел"

        try:
            jwt.decode(token, key=current_app.config['SECRET_KEY'],
                       algorithms=current_app.config['ALGORITHM'])
            return func(*args, **kwargs)
        except Exception:
            raise Exception

    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        token = request.headers.environ.get('HTTP_AUTHORIZATION').replace('Beaver ', '')

        if not token:
            return "Токен не пришел"

        try:
            data = jwt.decode(token, key=current_app.config['SECRET_KEY'],
                              algorithms=current_app.config['ALGORITHM'])
            if user_service.get_by_username(data['username']).role == "admin":
                return func(*args, **kwargs)
            else:
                return "У вас нет прав"
        except Exception:
            raise Exception

    return wrapper
