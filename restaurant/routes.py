import random
from restaurant import app, api
from flask import render_template, redirect, url_for, flash, request, session, Response
from restaurant.models import RestaurantManager, Table, User, Item, Order
from restaurant.forms import ManagerLoginForm, RegisterForm, LoginForm, OrderIDForm, ReserveForm, AddForm, OrderForm
from restaurant import db
from flask_login import login_user, logout_user, login_required, current_user

@app.route('/')
#HOME PAGE
@app.route('/home')
def home_page(): 
    return render_template('index.html')

#MENU PAGE
@app.route('/menu', defaults={'restaurant_name': None})
@app.route('/menu/<string:restaurant_name>')
def menu_page(restaurant_name):
    add_form = AddForm()
    if request.method == 'POST':
        selected_item = request.form.get('selected_item')
        s_item_object = db.session.query(Item).join(RestaurantManager, (Item.item_id == RestaurantManager.id)).filter(Item.name==selected_item, (RestaurantManager.restaurant_name1==restaurant_name or RestaurantManager.restaurant_name2==restaurant_name or RestaurantManager.restaurant_name3==restaurant_name)).first()
        if s_item_object:
            s_item_object.assign_ownership(current_user)
        return redirect(url_for('menu_page', restaurant_name=restaurant_name))

    if request.method == 'GET':
        restaurant_manager = RestaurantManager.query.filter((RestaurantManager.restaurant_name1==restaurant_name) | (RestaurantManager.restaurant_name2==restaurant_name) | (RestaurantManager.restaurant_name3==restaurant_name)).first()
        items = db.session.query(Item).join(RestaurantManager, (Item.item_id == RestaurantManager.id)).filter(RestaurantManager.restaurant_name1==restaurant_name or RestaurantManager.restaurant_name2==restaurant_name or RestaurantManager.restaurant_name3==restaurant_name).all()
        return render_template('menu.html', items=items, add_form=add_form, restaurant_name=restaurant_name, restaurant_manager=restaurant_manager)

@app.route('/cart', methods=['GET', 'POST'])
def cart_page():
    order_form = OrderForm()
    if request.method == 'POST':
        ordered_item = request.form.get('ordered_item')
        o_item_object = Item.query.filter_by(name=ordered_item).first()
        if o_item_object:
            order_info = Order(name=current_user.fullname,
                               address=current_user.address,
                               order_items=o_item_object.name)
            db.session.add(order_info)
            db.session.commit()
            o_item_object.remove_ownership(current_user)
        return redirect(url_for('congrats_page'))

    if request.method == 'GET':
        selected_items = Item.query.filter_by(orderer=current_user.id)
        return render_template('cart.html', order_form=order_form, selected_items=selected_items)

#CONGRATULATIONS PAGE
@app.route('/congrats')
def congrats_page():
    return render_template('congrats.html')   

#TABLE RESERVATION PAGE
@app.route('/table', methods=['GET', 'POST'])
@login_required
def table_page():
    reserve_form = ReserveForm()
    if request.method == 'POST':
        reserved_table = request.form.get('reserved_table')
        r_table_object = Table.query.filter_by(table=reserved_table).first()
        if r_table_object:
            r_table_object.assign_ownership(current_user)
        return redirect(url_for('table_page'))

    if request.method == 'GET':
        tables = Table.query.filter_by(reservee=None)
        return render_template('table.html', tables=tables, reserve_form=reserve_form)

#LOGIN PAGE
@app.route('/login', methods = ['GET', 'POST'])
def login_page():
    forml = LoginForm()
    form = RegisterForm()
    if forml.validate_on_submit():
        attempted_user = User.query.filter_by(username = forml.username.data).first() #get username data entered from sign in form
        if attempted_user and attempted_user.check_password_correction(attempted_password = forml.password.data): #to check if username & password entered is in user database
            login_user(attempted_user) #checks if user is registered 
            # flash(f'Signed in successfully as: {attempted_user.username}', category = 'success')
            return redirect(url_for('home_page'))
        else:
            flash('Username or password is incorrect! Please Try Again', category = 'danger') #displayed in case user is not registered
    return render_template('login.html', forml = forml, form = form)

#FORGOT PASSWORD
@app.route('/forgot', methods = ['GET', 'POST'])
def forgot():
    return render_template("forgot.html")

def return_login():
    return render_template("login.html")


#LOGOUT FUNCTIONALITY
@app.route('/logout')
def logout():
    logout_user() #used to log out
    flash('You have been logged out!', category = 'info')
    return redirect(url_for("home_page")) 

#REGISTER PAGE
@app.route('/register', methods = ['GET', 'POST'])
def register_page():
    forml = LoginForm()
    form = RegisterForm() 
    #checks if form is valid
    if form.validate_on_submit():
         user_to_create = User(username = form.username.data,
                               fullname = form.fullname.data,
                               address = form.address.data,
                               phone_number = form.phone_number.data,
                               password = form.password1.data,)
         db.session.add(user_to_create)
         db.session.commit()
         login_user(user_to_create) #login the user on registration 
         return redirect(url_for('verify'))
    # else:
    #     flash("Username already exists!")

    if form.errors != {}: #if there are not errors from the validations
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}')
    return render_template('login.html', form = form, forml = forml)



#OTP VERIFICATION

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if current_user.is_authenticated:
        country_code = "+91"
        phone_number = current_user.phone_number
        method = "sms"
        session['country_code'] = "+91"
        session['phone_number'] = current_user.phone_number

        api.phones.verification_start(phone_number, country_code, via=method)

        if request.method == "POST":
            token = request.form.get("token")
            phone_number = session.get("phone_number")
            country_code = session.get("country_code")

            verification = api.phones.verification_check(phone_number,
                                                         country_code,
                                                         token)

            if verification.ok():
                return render_template("index.html")
            else:
                flash('Your OTP is incorrect! Please Try Again', category='danger')

        return render_template("otp.html")
    else:
        flash('You need to be logged in to access this page.', category='danger')
        return redirect(url_for('login_page'))

#Manager Login
@app.route('/manager/login', methods=['GET', 'POST'])
def manager_login_page():
    form = ManagerLoginForm()
    if form.validate_on_submit():
        attempted_manager = RestaurantManager.query.filter_by(username=form.username.data).first()
        if attempted_manager:
            login_user(attempted_manager)
            flash(f'Signed in successfully as: {attempted_manager.username}', category='success')
            return redirect(url_for('manager_dashboard'))
        else:
            flash('Username or password is incorrect! Please Try Again', category='danger')
    return render_template('manager_login.html', form=form)

# Create a new route for the manager dashboard (you can add functionality here later)
@app.route('/manager/dashboard', defaults={'restaurant_manager': None})
@app.route('/manager/dashboard/<string:restaurant_manager>')
@login_required
def manager_dashboard(restaurant_manager):
    restaurant1 = RestaurantManager.restaurant_name1
    restaurant2 = RestaurantManager.restaurant_name2
    restaurant3 = RestaurantManager.restaurant_name3

    customer_name = User.username
    customer_fname = User.fullname
    customer_no = User.phone_number
    customer_email = User.address
    
    order_name = Item.name
    order_price = Item.price
    
    table = Table.table
    time = Table.time
    date = Table.date
    
    order_id = ''.join(random.choices('0123456789', k=6))
    session['order_id'] = order_id
    
    restaurant_manager_object = RestaurantManager.query.filter((RestaurantManager.restaurant_name1==restaurant_manager) | (RestaurantManager.restaurant_name2==restaurant_manager) | (RestaurantManager.restaurant_name3==restaurant_manager)).first()


    return render_template('manager_dashboard.html', restaurant_manager=restaurant_manager_object)

@app.route('/restaurants')
def restaurants():
    restaurants = RestaurantManager.query.all()
    return render_template('restaurants.html', restaurants=restaurants)


from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
import os
import smtplib

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'your_secret_key'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///restaurant.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'hungrydude283@gmail.com'
app.config['MAIL_PASSWORD'] = 'wqgs tnqx omnp komb'

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Sample data for restaurants and menus

# Helper function to send email
def send_email(recipient, subject, body):
    sender = app.config['MAIL_USERNAME']
    password = app.config['MAIL_PASSWORD']

    message = f'Subject: {subject}\n\n{body}'

    with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, recipient, message)

# Login and registration routes
# ... (same as before)

# Restaurant menu page
@app.route('/menu/<restaurant_id>', methods=['GET', 'POST'])
def menu(restaurant_id):
    restaurant = restaurants.get(restaurant_id)
    if not restaurant:
        flash('Invalid restaurant ID', 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Get the selected food items
        selected_items = request.form.getlist('food_items')

        # Simulate order confirmation and payment
        if selected_items:
            flash('Order confirmed! Your food will be ready in 30 minutes.', 'success')
            # Generate OTP
            #otp = random.randint(100000, 999999)

            # Get the logged-in user's email
            user = User.query.filter_by(username=request.form.get('username')).first()
            if user:
                recipient = user.email
                subject = 'Your Order Deatils are:'
                body = f'Order ID : 20100100\n'
                send_email(recipient, subject, body)
                flash('Receipt sent to the email address', 'info')
            else:
                flash('User not found.', 'error')
        else:
            flash('Please select at least one food item.', 'error')

    return render_template('menu.html', restaurant=restaurant)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)