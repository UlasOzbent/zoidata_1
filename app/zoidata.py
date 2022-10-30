from flask import Flask, render_template,url_for, request, redirect, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

from flask import flash 

from flask_bcrypt import Bcrypt

from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
import uuid as uuid
import os
from flask_wtf.file import FileField


app = Flask(__name__)
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zoi_login1.db'
"""app.config['SQLALCHEMY_BINDS'] = {'user' : 'sqlite:///zoi_user.db'
							   }"""


app.config['SECRET_KEY'] = 'zoidata'

db = SQLAlchemy(app)

@app.before_first_request
def create_tables():
	db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login2'

@login_manager.user_loader
def load_user(user_id):
	user = Login.query.filter_by(id=user_id).first()
	if user:
		return user
	return None


@property
def password(self):
	raise AttributeError('password is not a readable attribute!')

@password.setter
def password(self, password):
	self.password_hash = generate_password_hash(password)

def verify_password(self, password):
	return check_password_hash(self.password_hash, password)

# Create A String
def __repr__(self):
	return '<Name %r>' % self.name


class Login(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username= db.Column(db.String(200), nullable=False)
	password_hash = db.Column(db.String(120), nullable=False)
	model_pic = db.Column(db.String(), nullable=True)
	truefalse = db.Column(db.String(), nullable=True)
	date_added = db.Column(db.DateTime, default=datetime.utcnow)

	def __repr__(self):
		return '<Name %r>' % self.username


class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	password_hash = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Submit")

class UserForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	model_pic = FileField("Profile Pic")
	truefalse = StringField("Username", validators=[DataRequired()])
	submit = SubmitField("Submit")


@app.route('/zoi_login2', methods=['GET', 'POST'])
def login2():

	if current_user.is_authenticated:
		print("User is already logged in")
		return render_template('zoi_login4.html')

	form = LoginForm()
	if form.validate_on_submit():
		#hashed_password = bcrypt.generate_password_hash(form.password_hash.data)
		user = Login.query.filter_by(username=form.username.data).first()


		if user:
			# Check the hash
			password = user.password_hash
			password_check = bcrypt.check_password_hash(password, form.password_hash.data)
			username_ = user.username
		if user and password_check:
			login_user(user)
			#flash("Login Succesfull!! - Welcome " + username_)
			print(username_)
			return render_template('zoi_login3.html',username_=username_)
		
		else:
			flash("Wrong Password - Try Again!")
		
	return render_template('zoi_login2.html', form=form)

@app.route("/zoi_logout")
@login_required
def logout():
	if current_user.is_authenticated:
		
		logout_user()
		print("The user should have been LOGGED OUT NOW!!!")
		flash('You have successfully logged out. Have a nice day.', 'success')
	return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def login():
	
	if current_user.is_authenticated:
		print("User is already logged in")
		return render_template('zoi_login4.html')

	username = None 
	form = LoginForm()
	
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password_hash.data)
		user = Login.query.filter_by(username=form.username.data).first()
		if user is None:
			user = Login(username=form.username.data, password_hash=hashed_password)
			db.session.add(user)
			db.session.commit()
		username = form.username.data

	if request.method == 'POST':
		user_ = request.form.get('user')
		return redirect(url_for('login2', user_=user_))
	our_users = Login.query.order_by(Login.date_added)

	return render_template('zoi_login.html', form=form, username=username, our_users=our_users)

@app.route('/zoi_blog')
@login_required
def profile2():
	form = LoginForm()
	form2 = UserForm()
	id = current_user.id
	name_to_update = Login.query.get_or_404(id)

	return render_template('zoi_blog.html', form=form, form2=form2, name_to_update=name_to_update)

@app.route('/zoi_blog_update', methods=['GET', 'POST'])
@login_required
def profile():
	form = LoginForm()
	form2 = UserForm()
	id = current_user.id 
	print(current_user)
	name_to_update = Login.query.get_or_404(id)
	if request.method == 'POST':
		name_to_update.username = request.form['username']
		name_to_update.truefalse = request.form['truefalse']

		if request.files['model_pic']:
			name_to_update.model_pic = request.files['model_pic']

			pic_filename = secure_filename(name_to_update.model_pic.filename)

			pic_name = str(uuid.uuid1()) + "_" + pic_filename

			saver = request.files['model_pic']

			name_to_update.model_pic = pic_name

			try:
				db.session.commit()
				saver.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))
				flash('User updated successfully')
				print('update successfully')
				return render_template('zoi_blog.html', form=form, form2=form2, name_to_update=name_to_update)
			except:
				flash('Error')
				print('error')
				db.session.rollback()
				return render_template('zoi_blog_update.html', form=form, form2=form2, name_to_update=name_to_update)

		else:
			try:
				db.session.commit()
				flash('User updated successfully')
				print('succesful')
				return render_template('zoi_blog.html', form=form, form2=form2, name_to_update=name_to_update)
			except:
				db.session.rollback()
				print('rollback is successfully')
				return render_template('zoi_blog.html', form=form, form2=form2, name_to_update=name_to_update)
	else:
		return render_template('zoi_blog_update.html',form=form, form2=form2, name_to_update=name_to_update, id=id)


if __name__ == '__main__':
	app.run(host='127.0.0.1')