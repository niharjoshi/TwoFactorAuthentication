from flask import Flask, current_app, render_template, redirect, url_for, flash, session, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from twilio.rest import Client
import base64
import os
from werkzeug.security import generate_password_hash, check_password_hash
import onetimepass
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.fields import EmailField
from wtforms.validators import Email
from wtforms.validators import DataRequired, Length, EqualTo, Regexp
import pyqrcode
from io import BytesIO

app = Flask(__name__)
app.config.from_object("config")
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)


class User(UserMixin, db.Model):

    __table_name__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    email = db.Column(db.String(64), index=True)
    phone = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            self.otp_secret = base64.b32encode(os.urandom(10)).decode("utf-8")

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return "otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo".format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)


@lm.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(1, 64)])
    password = PasswordField("Password", validators=[DataRequired()])
    password_again = PasswordField("Password again", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Register")


class SMSForm(FlaskForm):
    phone = StringField("Phone", validators=[DataRequired(), Length(min=12, max=12), Regexp(regex="^\+[1-9]\d{1,14}$")])
    submit = SubmitField("Submit")


class SMSVerifyForm(FlaskForm):
    token = StringField("Token", validators=[DataRequired(), Length(6, 6)])
    submit = SubmitField("Verify")


class EmailForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Submit")


class EmailVerifyForm(FlaskForm):
    token = StringField("Token", validators=[DataRequired(), Length(6, 6)])
    submit = SubmitField("Verify")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(1, 64)])
    password = PasswordField("Password", validators=[DataRequired()])
    token = StringField("Token", validators=[DataRequired(), Length(6, 6)])
    submit = SubmitField("Login")


class TwoFactorForm(FlaskForm):
    auth_type = SelectField("Type of 2FA", choices=[("SMS", "SMS"), ("Email", "Email"), ("QR Code/Hardware Token", "QR Code/Hardware Token")])
    submit = SubmitField("Submit")


def _get_twilio_verify_client():
    return Client(os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"])


def request_sms_verification_token(phone):
    client = _get_twilio_verify_client()
    client.verify.services(os.environ["TWILIO_SMS_VERIFY_SERVICE_ID"]).verifications.create(to=phone, channel="sms")


def check_sms_verification_token(phone, token):
    client = _get_twilio_verify_client()
    result = client.verify.services(os.environ["TWILIO_SMS_VERIFY_SERVICE_ID"]).verification_checks.create(to=phone, code=token)
    return result.status


def request_email_verification_token(email):
    client = _get_twilio_verify_client()
    client.verify.services(os.environ["TWILIO_EMAIL_VERIFY_SERVICE_ID"]).verifications.create(to=email, channel="email")


def check_email_verification_token(email, token):
    client = _get_twilio_verify_client()
    result = client.verify.services(os.environ["TWILIO_EMAIL_VERIFY_SERVICE_ID"]).verification_checks.create(to=email, code=token)
    return result.status


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash("Username already exists.")
            return redirect(url_for("register"))
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        session["username"] = user.username
        return redirect(url_for("register_phone"))
    return render_template("register.html", form=form)


@app.route("/register_phone", methods=["GET", "POST"])
def register_phone():
    if "username" not in session:
        return redirect(url_for("index"))
    user = User.query.filter_by(username=session["username"]).first()
    if user is None:
        return redirect(url_for("index"))
    form = SMSForm()
    if form.validate_on_submit():
        session["phone"] = form.phone.data
        request_sms_verification_token(session["phone"])
        return redirect(url_for("verify_phone"))
    return render_template("register-phone.html", form=form)


@app.route("/verify_phone", methods=["GET", "POST"])
def verify_phone():
    if "username" not in session:
        return redirect(url_for("index"))
    user = User.query.filter_by(username=session["username"]).first()
    if user is None:
        return redirect(url_for("index"))
    form = SMSVerifyForm()
    if form.validate_on_submit():
        phone = session["phone"]
        if check_sms_verification_token(phone, form.token.data) == "approved":
            del session["phone"]
            current_user.phone = phone
            db.session.commit()
            flash("Phone number verified.")
            return redirect(url_for("register_email"))
        else:
            flash("Invalid token.")
            return redirect(url_for("register_phone"))
    return render_template("verify-phone.html", form=form)


@app.route("/register_email", methods=["GET", "POST"])
def register_email():
    if "username" not in session:
        return redirect(url_for("index"))
    user = User.query.filter_by(username=session["username"]).first()
    if user is None:
        return redirect(url_for("index"))
    form = EmailForm()
    if form.validate_on_submit():
        session["email"] = form.email.data
        request_email_verification_token(session["email"])
        return redirect(url_for("verify_email"))
    return render_template("register-email.html", form=form)


@app.route("/verify_email", methods=["GET", "POST"])
def verify_email():
    if "username" not in session:
        return redirect(url_for("index"))
    user = User.query.filter_by(username=session["username"]).first()
    if user is None:
        return redirect(url_for("index"))
    form = EmailVerifyForm()
    if form.validate_on_submit():
        email = session["email"]
        if check_email_verification_token(email, form.token.data) == "approved":
            del session["email"]
            current_user.email = email
            db.session.commit()
            flash("Email verified.")
            return redirect(url_for("two_factor_setup"))
        else:
            flash("Invalid token.")
            return redirect(url_for("register_email"))
    return render_template("verify-email.html", form=form)


@app.route("/twofactor")
def two_factor_setup():
    if "username" not in session:
        return redirect(url_for("index"))
    user = User.query.filter_by(username=session["username"]).first()
    if user is None:
        return redirect(url_for("index"))
    return render_template("two-factor-setup.html"), 200, {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }


@app.route("/qrcode")
def qrcode():
    if "username" not in session:
        abort(404)
    user = User.query.filter_by(username=session["username"]).first()
    if user is None:
        abort(404)
    del session["username"]
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        "Content-Type": "image/svg+xml",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data) or not user.verify_totp(form.token.data):
            flash("Invalid username, password or token.")
            return redirect(url_for("login"))
        login_user(user)
        flash("You are now logged in.")
        return redirect(url_for("index"))
    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


db.session.commit()
db.drop_all()
db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
