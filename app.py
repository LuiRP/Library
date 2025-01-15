from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt



app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=30)], render_kw={"placeholder": "Nombre de Usuario"})
    email = StringField(validators=[InputRequired(), Length(min=4,max=150)], render_kw={"placeholder": "Correo"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=30)], render_kw={"placeholder": "Contraseña"})

    submit = SubmitField("Registrarse")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Ese nombre de usuario ya existe. Porfavor utilize uno diferente.")
    
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("Ese correo electronico ya ha sido registrado. Porfavor utilize uno diferente.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=30)], render_kw={"placeholder": "Nombre de Usuario"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=30)], render_kw={"placeholder": "Contraseña"})

    submit = SubmitField("Iniciar Sesión")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('aprender'))

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/aprender', methods=['GET','POST'])
def aprender():
    return render_template('aprender.html')

@app.route('/comunidad', methods=['GET','POST'])
def comunidad():
    return render_template('comunidad.html')

@app.route('/mi_perfil', methods=['GET','POST'])
def mi_perfil():
    return render_template('mi_perfil.html')

@app.route('/course', methods=['GET','POST'])
def course():
    return render_template('course.html')

@app.route('/course2', methods=['GET','POST'])
def course2():
    return render_template('course2.html')

@app.route('/course3', methods=['GET','POST'])
def course3():
    return render_template('course3.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
