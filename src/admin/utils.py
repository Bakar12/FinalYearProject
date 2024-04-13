from flask import session, redirect, url_for
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('admin_routes.login_admin'))
        # Permission check logic here
        return f(*args, **kwargs)
    return decorated_function
