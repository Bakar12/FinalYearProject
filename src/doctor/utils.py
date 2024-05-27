from flask import session, redirect, url_for
from functools import wraps

def doctor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('doctor_routes.login_doctor'))
        # Permission check logic here
        return f(*args, **kwargs)
    return decorated_function
