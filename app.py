import re
from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask import flash
from flask import session
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, ValidationError
import logging
logging.basicConfig(filename='error.log', level=logging.ERROR)
from flask_bcrypt import Bcrypt
from wtforms import PasswordField

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///firstapp.db"

db = SQLAlchemy(app)

app.config['SECRET_KEY'] = 'supersecuresecretkey'   # Protects session & CSRF tokens

# Secure session settings
app.config['SESSION_COOKIE_SECURE'] = False   # Only sends cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True   # Prevents JS from stealing cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Blocks cross-site requests
 
# Optional but good
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 mins 

# enable CSRF
csrf = CSRFProtect(app)

# Import & Initialize bycrypt
bcrypt = Bcrypt(app)

class PersonForm(FlaskForm):
    fname = StringField('First Name', validators=[
        DataRequired(),
        Length(min=2, max=50),
        Regexp('^[A-Za-z]+$', message="Only letters allowed")
    ])
    lname = StringField('Last Name', validators=[
        DataRequired(),
        Length(min=2, max=50),
        Regexp('^[A-Za-z]+$', message="Only letters allowed")
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])
    password = PasswordField('Password', validators=[
    DataRequired(),
    Length(min=6)
    ])
    submit = SubmitField('Submit')

    # 🚨 Custom security validation
    def validate_fname(self, field):
        if re.search(r"(SELECT|INSERT|DELETE|DROP|--|'|<|>)", field.data, re.IGNORECASE):
            raise ValidationError("Invalid characters detected! Possible attack.")

    def validate_lname(self, field):
        if re.search(r"(SELECT|INSERT|DELETE|DROP|--|'|<|>)", field.data, re.IGNORECASE):
            raise ValidationError("Invalid characters detected! Possible attack.")

class FirstApp(db.Model):
    sno = db.Column(db.Integer, primary_key=True, autoincrement=True)
    fname = db.Column(db.String(100), nullable=False)
    lname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(200))

    def __repr__(self):
        return f"({self.sno}) {self.fname}"

@app.route('/', methods=['GET', 'POST'])
def hello_world():
    session.permanent = True   # session stays active for defined time - Controls session lifetime
    form = PersonForm()
    if form.validate_on_submit():  # only passes if validation succeeds
        # Hash password
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        firstapp = FirstApp(
            fname=form.fname.data,
            lname=form.lname.data,
            email=form.email.data,
            password=hashed_password
        )

        db.session.add(firstapp)
        db.session.commit()
        flash("Record added successfully!", "success")
        return redirect('/')
    elif request.method == 'POST':
        flash("Invalid input. Please check your entries.", "danger")

    allpeople = FirstApp.query.all()
    return render_template('index.html', allpeople=allpeople, form=form)

@app.route('/delete/<int:sno>')
def delete(sno):
    person = FirstApp.query.filter_by(sno=sno).first()
    db.session.delete(person)
    db.session.commit()
    return redirect('/')

@app.route('/update/<int:sno>', methods=['GET', 'POST'])
def update(sno):
    person = FirstApp.query.filter_by(sno=sno).first()
    form = PersonForm(obj=person)  # prefill form with existing values
    if form.validate_on_submit():
        person.fname = form.fname.data
        person.lname = form.lname.data
        person.email = form.email.data
        db.session.commit()

        # 🔐 ONLY update password if user entered one
        if form.password.data:
            person.password = bcrypt.generate_password_hash(
                form.password.data
            ).decode('utf-8')

        flash("Record updated successfully!", "success")
        return redirect('/')
    elif request.method == 'POST':
        flash("Invalid input. Please check your entries.", "danger")

    return render_template('update.html', form=form, person=person)

from sqlalchemy import text

# # ❌ VULNERABLE 
# @app.route('/unsafe')
# def unsafe():
#     name = request.args.get('name')
#     query = text(f"SELECT * FROM first_app WHERE fname = '{name}'")
    
#     result = db.session.execute(query)
#     return str(list(result))

# SAFE CODE TASK 2
@app.route('/safe')
def safe():
    name = request.args.get('name')
    query = text("SELECT * FROM first_app WHERE fname = :name")
    
    result = db.session.execute(query, {"name": name})
    return str(list(result))

@app.route("/home")
def home():
    return "<p>Welcome to home!</p>"

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    logging.error(str(e))
    return render_template('500.html'), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)