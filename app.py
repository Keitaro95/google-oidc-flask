from flask import Flask, request, render_template, redirect, url_for, Blueprint, session, flash
from flask_login import login_required, login_user, logout_user, LoginManager
from flask_dance.contrib.google import google
from google_auth_oauthlib.flow import Flow
import google.oauth2.credentials
from uuid import uuid4
import os, requests, hashlib

CLIENT_SECRET_FILE = 'credentials/client_secret.json'
SCOPES = ['openid', 'profile', 'email']
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

login_manager = LoginManager()

SECRET_KEY = str(uuid4())
app = Flask(__name__)
app.secret_key = SECRET_KEY
login_manager.init_app(app)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/authorize')
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
    )
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    authorization_url, state  = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent',
        state = hashlib.sha256(os.urandom(1024)).hexdigest()
        )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session.get('state')
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        state=state
    )
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes,
    }
    from google.oauth2 import id_token
    token_request = google.auth.transport.requests.Request()
    id_info = id_token.verify_oauth2_token(
        id_token=credentials.id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    email = id_info['email']
    # models.pyでUserクラスを作成したことを想定しています
    # user = User.select_by_email(email)
    # if not user:
    #     user = User(email=email)
    #     user.add_user()
    # login_user(user, remember=True)
    return redirect(url_for('inner'))


@app.route('/inner')
@login_required
def inner():
    return render_template('inner.html')


@app.route('/revoke')
@login_required
def revoke():
    if 'credentials' not in session:
        return redirect(url_for('app.authorize'))
    credentials = session['credentials']
    token = credentials['refresh_token']
    revoke = requests.post(
        "https://oauth2.googleapis.com/revoke",
        params={"token": token},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    # 状態を確認
    status_code = getattr(revoke, 'status_code')
    print(status_code)
    if status_code == 200:
        # tokenを削除
        del session['credentials']
        session.clear()
        # ログアウト
        logout_user()
        return redirect(url_for('home'))
    else:
        flash('An error occurred.')
        return redirect(url_for('inner'))
    


if __name__ == '__main__':
    app.run(debug=True)