from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, Length

##WTForm

class CreateRegisterForm(FlaskForm):
    valid_mail = Email(message="not valid email")
    valid_number = Length(min=4, message="min 4 characters")

    name = StringField("name", validators=[DataRequired()])
    email = StringField("email", validators=[DataRequired(), valid_mail])
    password = PasswordField("password", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class LoginForm(FlaskForm):
    valid_mail = Email(message="not valid email")
    valid_number = Length(min=4, message="min 4 characters")

    email = StringField("email", validators=[DataRequired(), valid_mail])
    password = PasswordField("password", validators=[DataRequired()])
    submit = SubmitField("Submit Post")