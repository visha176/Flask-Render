from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from app.models import Router
from wtforms import StringField, SelectField, SubmitField
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = SubmitField('Remember Me')
    submit = SubmitField('Login')

class AddRouterForm(FlaskForm):
    name = StringField('Router Name', validators=[DataRequired()])
    ip_address = StringField('IP Address', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Add Router')

class AddServerForm(FlaskForm):
    name = StringField('Server Name', validators=[DataRequired()])
    ip_address = StringField('IP Address', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    wireguard_address = StringField('WireGuard Address', validators=[DataRequired()])  # New field
    submit = SubmitField('Add Server')
    update = SubmitField('Update Server')  # New button

class AddWGConnectionForm(FlaskForm):
    connection_name = StringField('Connection Name', validators=[DataRequired()])
    router_id = SelectField('Router', validators=[DataRequired()], coerce=int)
    submit = SubmitField('Create Connection')

    def __init__(self):
        super().__init__()
        self.router_id.choices = [(router.id, router.name) for router in Router.query.all()]


class AddWGConnectionForm(FlaskForm):
    connection_name = StringField('Connection Name', validators=[DataRequired()])
    router_id = SelectField('Router', validators=[DataRequired()], coerce=int)
    submit = SubmitField('Create Connection')

    def __init__(self):
        super().__init__()
        self.router_id.choices = [(router.id, router.name) for router in Router.query.all()]

