import os
from flask import Flask, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
from flask_cors import CORS
from sqlalchemy.dialects.sqlite import JSON
import json
from flask_migrate import Migrate
import openai

app = Flask(__name__)
# change to secure key in prod
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///store.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Enable CORS for all routes and allow credentials
CORS(app, supports_credentials=True)

# Stripe config - set your stripe keys here or via environment variables
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY")

# OpenAI config - set your OpenAI API key here or via environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
openai.api_key = OPENAI_API_KEY

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)

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
    brand = db.Column(db.String(100), nullable=True)
    price = db.Column(db.Float, nullable=False)
    originalPrice = db.Column(db.Float, nullable=True)
    image_url = db.Column(db.String(300), nullable=True)
    badge = db.Column(db.String(50), nullable=True)
    badgeColor = db.Column(db.String(50), nullable=True)
    category = db.Column(db.String(50), nullable=True)
    concerns = db.Column(JSON, nullable=True)
    description = db.Column(db.Text, nullable=True)
    ingredients = db.Column(JSON, nullable=True)
    howToUse = db.Column(db.Text, nullable=True)
    benefits = db.Column(JSON, nullable=True)
    skinType = db.Column(db.String(100), nullable=True)


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey(
        'product.id'), nullable=False)
    stripe_session_id = db.Column(db.String(255), nullable=False)
    payment_intent = db.Column(db.String(255), nullable=True)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), default='usd')
    # e.g., 'paid', 'refunded'
    status = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    refunded_at = db.Column(db.DateTime, nullable=True)
    refund_id = db.Column(db.String(255), nullable=True)  # Stripe refund ID
    # Optionally, store more Stripe metadata as needed


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey(
        'product.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5
    review = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    # Optionally, enforce one review per user per product with a unique constraint
    __table_args__ = (db.UniqueConstraint(
        'user_id', 'product_id', name='_user_product_review_uc'),)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper: admin_required decorator


def admin_required(func):
    from functools import wraps

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'error': 'Admin access required.'}), 403
        return func(*args, **kwargs)
    return decorated_view

# API Endpoints


@app.route('/api/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([
        {
            'id': p.id,
            'name': p.name,
            'description': p.description,
            'price': p.price,
            'image_url': p.image_url,
            'category': p.category,
            'brand': p.brand,
            'badge': p.badge,
            'badgeColor': p.badgeColor,
        }
        for p in products
    ])


@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify({
        'id': product.id,
        'name': product.name,
        'brand': product.brand,
        'price': product.price,
        'originalPrice': product.originalPrice,
        'image_url': product.image_url,
        'badge': product.badge,
        'badgeColor': product.badgeColor,
        'category': product.category,
        'concerns': product.concerns,
        'description': product.description,
        'ingredients': product.ingredients,
        'howToUse': product.howToUse,
        'benefits': product.benefits,
        'skinType': product.skinType,
    })


@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password required.'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered.'}), 400
    user = User(email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'Registration successful.'}), 201


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    # default to True for persistent login
    remember = data.get('remember', True)
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        login_user(user, remember=remember)
        return jsonify({'message': 'Logged in successfully.'})
    else:
        return jsonify({'error': 'Invalid email or password.'}), 401


@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully.'})


@app.route('/api/admin/products', methods=['POST'])
@admin_required
def create_product():
    data = request.json
    product = Product(
        name=data.get('name'),
        brand=data.get('brand'),
        price=float(data.get('price')),
        originalPrice=float(data['originalPrice']) if data.get(
            'originalPrice') else None,
        image_url=data.get('image_url'),
        badge=data.get('badge'),
        badgeColor=data.get('badgeColor'),
        category=data.get('category'),
        concerns=data.get('concerns'),
        description=data.get('description'),
        ingredients=data.get('ingredients'),
        howToUse=data.get('howToUse'),
        benefits=data.get('benefits'),
        skinType=data.get('skinType'),
    )
    db.session.add(product)
    db.session.commit()
    return jsonify({'message': 'Product created successfully.', 'id': product.id}), 201


@app.route('/api/admin/products/<int:product_id>', methods=['PUT'])
@admin_required
def update_product(product_id):
    product = Product.query.get_or_404(product_id)
    data = request.json
    product.name = data.get('name', product.name)
    product.brand = data.get('brand', product.brand)
    product.price = float(data.get('price', product.price))
    product.originalPrice = float(data['originalPrice']) if data.get(
        'originalPrice') else product.originalPrice
    product.image_url = data.get('image_url', product.image_url)
    product.badge = data.get('badge', product.badge)
    product.badgeColor = data.get('badgeColor', product.badgeColor)
    product.category = data.get('category', product.category)
    product.concerns = data.get('concerns', product.concerns)
    product.description = data.get('description', product.description)
    product.ingredients = data.get('ingredients', product.ingredients)
    product.howToUse = data.get('howToUse', product.howToUse)
    product.benefits = data.get('benefits', product.benefits)
    product.skinType = data.get('skinType', product.skinType)
    db.session.commit()
    return jsonify({'message': 'Product updated successfully.'})


@app.route('/api/admin/products/<int:product_id>', methods=['DELETE'])
@admin_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully.'})


@app.route('/api/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    data = request.json
    cart_items = data.get('cartItems', [])
    if not cart_items or not isinstance(cart_items, list):
        return jsonify({'error': 'No cart items provided'}), 400
    line_items = []
    for item in cart_items:
        product = Product.query.get(item.get('id'))
    if not product:
        return jsonify({'error': f'Invalid product ID: {item.get("id")}'}), 400
    line_items.append({
        'price_data': {
            'currency': 'usd',
            'unit_amount': int(product.price * 100),
            'product_data': {
                        'name': product.name,
                        'description': product.description or '',
                        'images': [product.image_url] if product.image_url else [],
            },
        },
        'quantity': item.get('quantity', 1),
    })
    product_ids = ','.join(str(item['id']) for item in cart_items)
    quantities = ','.join(str(item['quantity']) for item in cart_items)
    metadata = {
        'product_ids': product_ids,
        'quantities': quantities
    }
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=line_items,
            mode='payment',
            success_url=url_for('payment_success', _external=True),
            cancel_url=url_for('get_products', _external=True),
            customer_email=current_user.email,
            metadata=metadata
        )
        return jsonify({'id': checkout_session.id, 'url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/payment-success', methods=['GET'])
@login_required
def payment_success():
    # Return a simple HTML page with a success message and a button to go home
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Payment Successful</title>
        <style>
            body { background: #fff0f6; color: #d6336c; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
            .container { background: #fff; padding: 2rem 3rem; border-radius: 1rem; box-shadow: 0 2px 16px #f8bbd0; text-align: center; }
            h1 { font-size: 2.5rem; margin-bottom: 1rem; }
            p { font-size: 1.2rem; margin-bottom: 2rem; }
            a.button { display: inline-block; background: #d6336c; color: #fff; padding: 0.75rem 2rem; border-radius: 0.5rem; text-decoration: none; font-weight: bold; font-size: 1.1rem; transition: background 0.2s; }
            a.button:hover { background: #a61e4d; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Payment Successful!</h1>
            <p>Thank you for your purchase. Your payment was processed successfully.</p>
            <a href="http://localhost:5173" class="button">Back to Home</a>
        </div>
    </body>
    </html>
    '''


@app.route('/api/user', methods=['GET'])
@login_required
def get_user():
    return jsonify({
        'email': current_user.email,
        'is_admin': current_user.is_admin
    })


@app.route('/api/products/<int:product_id>/related', methods=['GET'])
def get_related_products(product_id):
    product = Product.query.get_or_404(product_id)
    related = Product.query.filter(
        Product.category == product.category,
        Product.id != product.id
    ).limit(4).all()
    return jsonify([
        {
            'id': p.id,
            'name': p.name,
            'brand': p.brand,
            'price': p.price,
            'originalPrice': p.originalPrice,
            'image_url': p.image_url,
            'badge': p.badge,
            'badgeColor': p.badgeColor,
            'category': p.category,
            'concerns': p.concerns,
            'description': p.description,
            'ingredients': p.ingredients,
            'howToUse': p.howToUse,
            'benefits': p.benefits,
            'skinType': p.skinType,
        }
        for p in related
    ])


@app.route('/api/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('stripe-signature')
    endpoint_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
    if not endpoint_secret:
        print('ERROR: STRIPE_WEBHOOK_SECRET environment variable is not set!')
        return 'Webhook secret not set', 500
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        print('Invalid payload:', e)
        return '', 400
    except stripe.error.SignatureVerificationError as e:
        print('Invalid signature:', e)
        return '', 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        print('Received checkout.session.completed event:')
        print(json.dumps(session, indent=2))
        # You must set up your Stripe checkout session to include product_ids and quantities in metadata
        # Example: metadata = { 'product_ids': '1,2,3', 'quantities': '2,1,1' }
        product_ids = session.get('metadata', {}).get('product_ids', '')
        quantities = session.get('metadata', {}).get('quantities', '')
        product_id_list = [int(pid) for pid in product_ids.split(',') if pid]
        quantity_list = [int(q) for q in quantities.split(',') if q]
        user_email = session.get('customer_email')
        stripe_session_id = session.get('id')
        payment_intent = session.get('payment_intent')
        amount_total = session.get(
            'amount_total', 0) / 100.0  # Stripe uses cents
        currency = session.get('currency', 'usd')
        status = session.get('payment_status', 'unpaid')

        user = None
        if user_email:
            user = User.query.filter_by(email=user_email).first()
        if user and product_id_list and quantity_list and len(product_id_list) == len(quantity_list):
            for pid, qty in zip(product_id_list, quantity_list):
                product = Product.query.get(pid)
                if product:
                    transaction = Transaction(
                        user_id=user.id,
                        product_id=product.id,
                        stripe_session_id=stripe_session_id,
                        payment_intent=payment_intent,
                        amount=product.price * qty,
                        currency=currency,
                        status=status
                    )
                    db.session.add(transaction)
            db.session.commit()
    return '', 200


@app.route('/api/admin/transactions', methods=['GET'])
@admin_required
def list_transactions():
    transactions = Transaction.query.order_by(
        Transaction.created_at.desc()).all()
    result = []
    for t in transactions:
        user = User.query.get(t.user_id)
        product = Product.query.get(t.product_id)
        result.append({
            'id': t.id,
            'user_email': user.email if user else None,
            'product_name': product.name if product else None,
            'product_image_url': product.image_url if product else None,
            'product_category': product.category if product else None,
            'product_brand': product.brand if product else None,
            'product_badge': product.badge if product else None,
            'amount': t.amount,
            'currency': t.currency,
            'status': t.status,
            'created_at': t.created_at,
            'refunded_at': t.refunded_at,
            'refund_id': t.refund_id,
        })
    return jsonify(result)


@app.route('/api/admin/transactions/<int:transaction_id>/refund', methods=['POST'])
@admin_required
def refund_transaction(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    if transaction.status == 'refunded':
        return jsonify({'error': 'Already refunded'}), 400
    try:
        # Refund via Stripe
        refund = stripe.Refund.create(
            payment_intent=transaction.payment_intent)
        transaction.status = 'refunded'
        transaction.refunded_at = db.func.now()
        transaction.refund_id = refund.id
        db.session.commit()
        return jsonify({'message': 'Refund successful', 'refund_id': refund.id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai-recommendations', methods=['POST'])
def ai_recommendations():
    data = request.json
    user_info = data.get('user_info')
    # Only get the first 20 products and only essential fields
    products = Product.query.limit(20).all()
    products_list = [
        {
            'id': p.id,
            'name': p.name,
            'brand': p.brand,
            'price': p.price,
            'category': p.category,
            'badge': p.badge,
            'skinType': p.skinType,
            'concerns': p.concerns,
        }
        for p in products
    ]
    if not user_info or not products_list:
        return jsonify({'error': 'Missing user_info or products'}), 400

    system_prompt = f"""
You are a helpful beauty consultant AI. Consider the preferences of the user and the following product list to recommend the best products.

Product list:
{json.dumps(products_list, indent=2)}
"""
    user_prompt = f"""
Based on the user's profile, recommend the top 3 products and explain why for each. Return a JSON array of objects with fields: product_id, reason, and matchScore (0-100).

User profile:
{json.dumps(user_info, indent=2)}

Respond with only the JSON array.
"""
    try:
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "system", "content": system_prompt},
                      {"role": "user", "content": user_prompt}],
            temperature=0.7,
        )
        # Extract the JSON from the response
        import re
        import ast
        content = response.choices[0].message.content
        # Try to extract JSON array from the response
        match = re.search(r'(\[.*\])', content, re.DOTALL)
        if match:
            recommendations = ast.literal_eval(match.group(1))
        else:
            recommendations = []

        # Fetch product details for each recommended product_id
        recs_with_products = []
        for rec in recommendations:
            product = Product.query.get(rec.get('product_id'))
            if product:
                product_dict = {
                    'id': product.id,
                    'name': product.name,
                    'brand': product.brand,
                    'price': product.price,
                    'originalPrice': product.originalPrice,
                    'image_url': product.image_url,
                    'badge': product.badge,
                    'badgeColor': product.badgeColor,
                    'category': product.category,
                    'concerns': product.concerns,
                    'description': product.description,
                    'ingredients': product.ingredients,
                    'howToUse': product.howToUse,
                    'benefits': product.benefits,
                    'skinType': product.skinType,
                }
                recs_with_products.append({
                    'product': product_dict,
                    'reason': rec.get('reason'),
                    'matchScore': rec.get('matchScore'),
                })
        return jsonify({'recommendations': recs_with_products})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error handlers


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'error': 'Not found'}), 404

# Initialize DB command (run once)


@app.cli.command("init-db")
def init_db():
    db.create_all()
    # Create admin user for demo if none exists
    admin_email = "admin@admin.com"
    if not User.query.filter_by(email=admin_email).first():
        admin = User(email=admin_email, is_admin=True)
        admin.set_password('admin@admin.com')  # change password!
        db.session.add(admin)
        db.session.commit()
        print('Admin user created with email admin@example.com and password adminpass')
    else:
        print('Admin user already exists.')
    print("Database initialized.")


if __name__ == '__main__':
    app.run(debug=True)
