import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, DecimalField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange
import stripe

app = Flask(__name__)
# change to secure key in prod
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///store.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Stripe config - set your stripe keys here or via environment variables
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY")

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(300), nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[
                        DataRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
                        DataRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    price = DecimalField('Price (USD)', validators=[
                         DataRequired(), NumberRange(min=0)])
    image_url = StringField('Image URL')
    submit = SubmitField('Save')

# Routes


@app.route('/')
def home():
    products = Product.query.all()
    return render_template('home.html', products=products, stripe_public_key=STRIPE_PUBLIC_KEY)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        user = User(email=form.email.data)
        user.set_password(form.password.data)
        # Normal users are not admin by default
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next') or url_for('home')
            return redirect(next_page)
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('home'))

# Admin dashboard and product management


def admin_required(func):
    """Decorator to restrict route to admin only."""
    from functools import wraps

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required.', 'warning')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return decorated_view


@app.route('/admin')
@admin_required
def admin_dashboard():
    products = Product.query.all()
    return render_template('admin/dashboard.html', products=products)


@app.route('/admin/product/new', methods=['GET', 'POST'])
@admin_required
def new_product():
    form = ProductForm()
    if form.validate_on_submit():
        product = Product(
            name=form.name.data,
            description=form.description.data,
            price=float(form.price.data),
            image_url=form.image_url.data or None
        )
        db.session.add(product)
        db.session.commit()
        flash('Product created successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/product_form.html', form=form, title='New Product')


@app.route('/admin/product/<int:product_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product)
    if form.validate_on_submit():
        product.name = form.name.data
        product.description = form.description.data
        product.price = float(form.price.data)
        product.image_url = form.image_url.data or None
        db.session.commit()
        flash('Product updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/product_form.html', form=form, title='Edit Product')


@app.route('/admin/product/<int:product_id>/delete', methods=['POST'])
@admin_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully.', 'info')
    return redirect(url_for('admin_dashboard'))

# Payment Route


@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    data = request.json
    product_id = data.get('product_id')
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Invalid product ID'}), 400

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'unit_amount': int(product.price * 100),
                    'product_data': {
                        'name': product.name,
                        'description': product.description or '',
                        'images': [product.image_url] if product.image_url else [],
                    },
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('payment_success', _external=True),
            cancel_url=url_for('home', _external=True),
            customer_email=current_user.email
        )
        return jsonify({'id': checkout_session.id})
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route('/payment-success')
@login_required
def payment_success():
    flash('Payment successful! Thank you for your purchase.', 'success')
    return redirect(url_for('home'))

# Error handlers


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Initialize DB command (run once)


@app.cli.command("init-db")
def init_db():
    db.create_all()
    # Create admin user for demo if none exists
    admin_email = "admin@example.com"
    if not User.query.filter_by(email=admin_email).first():
        admin = User(email=admin_email, is_admin=True)
        admin.set_password('adminpass')  # change password!
        db.session.add(admin)
        db.session.commit()
        print('Admin user created with email admin@example.com and password adminpass')
    else:
        print('Admin user already exists.')
    print("Database initialized.")


if __name__ == '__main__':
    app.run(debug=True)
