from flask import render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory
from app import app, db
from models import MenuItem, User, Order, Promotion
from datetime import datetime, timedelta
import uuid
import re
from functools import wraps
import json

# Store status
store_status = {'open': True}

# Input validation helpers
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    pattern = r'^[0-9]{10,15}$'
    return re.match(pattern, phone.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')) is not None

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def delivery_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_delivery:
            flash('Access denied. Delivery team privileges required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Context processor
@app.context_processor
def inject_current_user():
    def get_current_user():
        if 'user_id' in session:
            return User.query.get(session['user_id'])
        return None
    return dict(get_current_user=get_current_user)

# Security headers
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"
    return response

# Routes
@app.route('/')
def home():
    menu_items = MenuItem.query.filter_by(in_stock=True).order_by(MenuItem.popularity.desc()).limit(6).all()
    categories = db.session.query(MenuItem.category).distinct().all()
    categories = [cat[0] for cat in categories]
    
    return render_template('home.html', 
                         title='Biryani Club - Authentic Flavors',
                         menu_items=menu_items,
                         categories=categories,
                         store_open=store_status['open'])

@app.route('/menu')
def menu():
    category = request.args.get('category', 'all')
    search = request.args.get('search', '')
    
    query = MenuItem.query.filter_by(in_stock=True)
    
    if category != 'all':
        query = query.filter_by(category=category)
    
    if search:
        query = query.filter(MenuItem.name.contains(search))
    
    menu_items = query.order_by(MenuItem.popularity.desc()).all()
    categories = db.session.query(MenuItem.category).distinct().all()
    categories = [cat[0] for cat in categories]
    
    return render_template('menu.html',
                         title='Our Menu - Biryani Club',
                         menu_items=menu_items,
                         categories=categories,
                         current_category=category,
                         search_term=search,
                         store_open=store_status['open'])

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if not store_status['open']:
        flash('Sorry, we are currently closed! No new orders accepted.', 'warning')
        return redirect(url_for('menu'))
    
    item_id = request.form.get('item_id', type=int)
    quantity = request.form.get('quantity', 1, type=int)
    
    if not item_id or quantity <= 0:
        flash('Invalid item or quantity', 'danger')
        return redirect(url_for('menu'))
    
    item = MenuItem.query.get_or_404(item_id)
    
    if not item.in_stock:
        flash(f'{item.name} is currently out of stock', 'warning')
        return redirect(url_for('menu'))
    
    # Initialize cart if not exists
    if 'cart' not in session:
        session['cart'] = {}
    
    # Add item to cart
    cart = session['cart']
    item_key = str(item_id)
    
    if item_key in cart:
        cart[item_key]['quantity'] += quantity
    else:
        cart[item_key] = {
            'name': item.name,
            'price': item.price,
            'quantity': quantity,
            'emoji': item.emoji
        }
    
    session['cart'] = cart
    session.modified = True
    
    flash(f'Added {item.name} to cart!', 'success')
    return redirect(url_for('menu'))

@app.route('/cart')
def cart():
    cart_items = []
    subtotal = 0
    
    if 'cart' in session and session['cart']:
        for item_id, item_data in session['cart'].items():
            item_total = item_data['price'] * item_data['quantity']
            cart_items.append({
                'id': item_id,
                'name': item_data['name'],
                'price': item_data['price'],
                'quantity': item_data['quantity'],
                'total': item_total,
                'emoji': item_data.get('emoji', '🍽️')
            })
            subtotal += item_total
    
    return render_template('cart.html',
                         title='Shopping Cart - Biryani Club',
                         cart_items=cart_items,
                         subtotal=subtotal,
                         store_open=store_status['open'])

@app.route('/update_cart', methods=['POST'])
def update_cart():
    item_id = request.form.get('item_id')
    quantity = request.form.get('quantity', type=int)
    
    if 'cart' in session and item_id in session['cart']:
        if quantity <= 0:
            del session['cart'][item_id]
            flash('Item removed from cart', 'info')
        else:
            session['cart'][item_id]['quantity'] = quantity
            flash('Cart updated', 'success')
        
        session.modified = True
    
    return redirect(url_for('cart'))

@app.route('/clear_cart')
def clear_cart():
    session.pop('cart', None)
    flash('Cart cleared', 'info')
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if not store_status['open']:
        flash('Sorry, we are currently closed! Cannot process orders.', 'warning')
        return redirect(url_for('menu'))
        
    if 'cart' not in session or not session['cart']:
        flash('Your cart is empty', 'warning')
        return redirect(url_for('menu'))
    
    if request.method == 'POST':
        # Get form data
        customer_name = request.form.get('customer_name', '').strip()
        customer_phone = request.form.get('customer_phone', '').strip()
        customer_address = request.form.get('customer_address', '').strip()
        payment_method = request.form.get('payment_method', '')
        coupon_code = request.form.get('coupon_code', '').strip()
        
        # Validation
        if not all([customer_name, customer_phone, customer_address, payment_method]):
            flash('Please fill in all required fields', 'danger')
            return redirect(url_for('checkout'))
        
        if not validate_phone(customer_phone):
            flash('Please enter a valid phone number', 'danger')
            return redirect(url_for('checkout'))
        
        # Calculate totals
        cart_items = []
        subtotal = 0
        
        for item_id, item_data in session['cart'].items():
            item_total = item_data['price'] * item_data['quantity']
            cart_items.append({
                'id': item_id,
                'name': item_data['name'],
                'price': item_data['price'],
                'quantity': item_data['quantity'],
                'total': item_total
            })
            subtotal += item_total
        
        # Apply coupon if provided
        discount = 0
        if coupon_code:
            promotion = Promotion.query.filter_by(code=coupon_code.upper()).first()
            if promotion and promotion.is_valid():
                discount = promotion.calculate_discount(subtotal)
                if discount > 0:
                    promotion.usage_count += 1
                    flash(f'Coupon applied! You saved ₹{discount:.2f}', 'success')
                else:
                    flash('Coupon not applicable to this order', 'warning')
            else:
                flash('Invalid or expired coupon code', 'warning')
        
        total = subtotal - discount
        
        # Create order
        order_id = f'BC{datetime.now().strftime("%Y%m%d")}{uuid.uuid4().hex[:6].upper()}'
        
        order = Order(
            order_id=order_id,
            customer_name=customer_name,
            customer_phone=customer_phone,
            customer_address=customer_address,
            subtotal=subtotal,
            discount=discount,
            total=total,
            payment_method=payment_method,
            coupon_code=coupon_code.upper() if coupon_code else None,
            user_id=session.get('user_id'),
            estimated_delivery=datetime.utcnow() + timedelta(minutes=30)
        )
        order.set_items(cart_items)
        
        db.session.add(order)
        
        # Update item popularity
        for item_id, item_data in session['cart'].items():
            item = MenuItem.query.get(int(item_id))
            if item:
                item.popularity += item_data['quantity']
        
        # Add loyalty points if user is logged in
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user:
                points_earned = int(total / 10)  # 1 point per ₹10 spent
                user.loyalty_points += points_earned
                
                # Update tier based on points
                if user.loyalty_points >= 1000:
                    user.loyalty_tier = 'gold'
                elif user.loyalty_points >= 500:
                    user.loyalty_tier = 'silver'
                
                flash(f'You earned {points_earned} loyalty points!', 'info')
        
        db.session.commit()
        
        # Clear cart
        session.pop('cart', None)
        
        flash(f'Order placed successfully! Your order ID is {order_id}', 'success')
        return redirect(url_for('order_confirmation', order_id=order_id))
    
    # GET request - show checkout form
    cart_items = []
    subtotal = 0
    
    for item_id, item_data in session['cart'].items():
        item_total = item_data['price'] * item_data['quantity']
        cart_items.append({
            'id': item_id,
            'name': item_data['name'],
            'price': item_data['price'],
            'quantity': item_data['quantity'],
            'total': item_total,
            'emoji': item_data.get('emoji', '🍽️')
        })
        subtotal += item_total
    
    return render_template('cart.html',
                         title='Checkout - Biryani Club',
                         cart_items=cart_items,
                         subtotal=subtotal,
                         checkout=True,
                         store_open=store_status['open'])

@app.route('/order_confirmation/<order_id>')
def order_confirmation(order_id):
    order = Order.query.filter_by(order_id=order_id).first_or_404()
    return render_template('user/orders.html',
                         title='Order Confirmation',
                         orders=[order],
                         single_order=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password', 'danger')
            return render_template('login.html', title='Login - Biryani Club')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session.permanent = True
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash(f'Welcome back, {user.full_name or user.username}!', 'success')
            
            # Redirect based on user role
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            elif user.is_delivery:
                return redirect(url_for('delivery_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html', title='Login - Biryani Club')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()
        
        # Validation
        if not all([username, email, password, confirm_password]):
            flash('Please fill in all required fields', 'danger')
            return render_template('register.html', title='Register - Biryani Club')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html', title='Register - Biryani Club')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return render_template('register.html', title='Register - Biryani Club')
        
        if not validate_email(email):
            flash('Please enter a valid email address', 'danger')
            return render_template('register.html', title='Register - Biryani Club')
        
        if phone and not validate_phone(phone):
            flash('Please enter a valid phone number', 'danger')
            return render_template('register.html', title='Register - Biryani Club')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html', title='Register - Biryani Club')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return render_template('register.html', title='Register - Biryani Club')
        
        # Create new user
        user = User(
            username=username,
            email=email,
            full_name=full_name,
            phone=phone
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register - Biryani Club')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        
        # Validation
        if phone and not validate_phone(phone):
            flash('Please enter a valid phone number', 'danger')
            return redirect(url_for('profile'))
        
        # Update user info
        user.full_name = full_name
        user.phone = phone
        user.address = address
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    recent_orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).limit(5).all()
    
    return render_template('user/profile.html',
                         title='My Profile - Biryani Club',
                         user=user,
                         recent_orders=recent_orders)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    user = User.query.get(session['user_id'])
    
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # Validation
    if not user.check_password(current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('profile'))
    
    if len(new_password) < 6:
        flash('New password must be at least 6 characters long', 'danger')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('profile'))
    
    # Update password
    user.set_password(new_password)
    db.session.commit()
    
    flash('Password changed successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/my_orders')
@login_required
def my_orders():
    user = User.query.get(session['user_id'])
    orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()
    
    return render_template('user/orders.html',
                         title='My Orders - Biryani Club',
                         orders=orders)

@app.route('/rate_order', methods=['POST'])
@login_required
def rate_order():
    order_id = request.form.get('order_id', type=int)
    rating = request.form.get('rating', type=int)
    feedback = request.form.get('feedback', '').strip()
    
    if not order_id or not rating or rating < 1 or rating > 5:
        flash('Invalid rating data', 'danger')
        return redirect(url_for('my_orders'))
    
    order = Order.query.filter_by(id=order_id, user_id=session['user_id']).first()
    
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('my_orders'))
    
    if order.status != 'delivered':
        flash('Can only rate delivered orders', 'warning')
        return redirect(url_for('my_orders'))
    
    order.rating = rating
    order.feedback = feedback
    db.session.commit()
    
    flash('Thank you for your feedback!', 'success')
    return redirect(url_for('my_orders'))

# Admin routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    # Dashboard statistics
    total_orders = Order.query.count()
    total_revenue = db.session.query(db.func.sum(Order.total)).scalar() or 0
    total_customers = User.query.filter_by(is_admin=False, is_delivery=False).count()
    pending_orders = Order.query.filter_by(status='pending').count()
    
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    popular_items = MenuItem.query.order_by(MenuItem.popularity.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         title='Admin Dashboard - Biryani Club',
                         total_orders=total_orders,
                         total_revenue=total_revenue,
                         total_customers=total_customers,
                         pending_orders=pending_orders,
                         recent_orders=recent_orders,
                         popular_items=popular_items)

@app.route('/admin/menu')
@admin_required
def admin_menu():
    menu_items = MenuItem.query.order_by(MenuItem.category, MenuItem.name).all()
    categories = db.session.query(MenuItem.category).distinct().all()
    categories = [cat[0] for cat in categories]
    
    return render_template('admin/menu_manage.html',
                         title='Manage Menu - Admin',
                         menu_items=menu_items,
                         categories=categories)

@app.route('/admin/menu/add', methods=['POST'])
@admin_required
def admin_add_menu_item():
    name = request.form.get('name', '').strip()
    category = request.form.get('category', '').strip()
    price = request.form.get('price', type=float)
    description = request.form.get('description', '').strip()
    emoji = request.form.get('emoji', '🍽️').strip()
    
    if not all([name, category, price]):
        flash('Name, category, and price are required', 'danger')
        return redirect(url_for('admin_menu'))
    
    if price <= 0:
        flash('Price must be greater than 0', 'danger')
        return redirect(url_for('admin_menu'))
    
    # Check if item already exists
    if MenuItem.query.filter_by(name=name).first():
        flash('Menu item with this name already exists', 'danger')
        return redirect(url_for('admin_menu'))
    
    item = MenuItem(
        name=name,
        category=category,
        price=price,
        description=description,
        emoji=emoji
    )
    
    db.session.add(item)
    db.session.commit()
    
    flash(f'Menu item "{name}" added successfully!', 'success')
    return redirect(url_for('admin_menu'))

@app.route('/admin/menu/update/<int:item_id>', methods=['POST'])
@admin_required
def admin_update_menu_item(item_id):
    item = MenuItem.query.get_or_404(item_id)
    
    item.name = request.form.get('name', item.name).strip()
    item.category = request.form.get('category', item.category).strip()
    item.price = request.form.get('price', item.price, type=float)
    item.description = request.form.get('description', item.description).strip()
    item.emoji = request.form.get('emoji', item.emoji).strip()
    item.in_stock = 'in_stock' in request.form
    
    db.session.commit()
    flash(f'Menu item "{item.name}" updated successfully!', 'success')
    return redirect(url_for('admin_menu'))

@app.route('/admin/menu/delete/<int:item_id>')
@admin_required
def admin_delete_menu_item(item_id):
    item = MenuItem.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash(f'Menu item "{item.name}" deleted successfully!', 'success')
    return redirect(url_for('admin_menu'))

@app.route('/admin/orders')
@admin_required
def admin_orders():
    status_filter = request.args.get('status', 'all')
    
    query = Order.query
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    orders = query.order_by(Order.created_at.desc()).all()
    
    # Get delivery persons for assignment
    delivery_persons = User.query.filter_by(is_delivery=True).all()
    
    return render_template('admin/orders.html',
                         title='Manage Orders - Admin',
                         orders=orders,
                         current_status=status_filter,
                         delivery_persons=delivery_persons)

@app.route('/admin/orders/update/<int:order_id>', methods=['POST'])
@admin_required
def admin_update_order(order_id):
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')
    
    if new_status in ['pending', 'confirmed', 'preparing', 'out_for_delivery', 'delivered', 'cancelled']:
        order.status = new_status
        
        # Assign delivery person if status is out_for_delivery
        if new_status == 'out_for_delivery':
            delivery_person_id = request.form.get('delivery_person_id', type=int)
            if delivery_person_id:
                order.delivery_person_id = delivery_person_id
        
        db.session.commit()
        flash(f'Order {order.order_id} status updated to {new_status.replace("_", " ").title()}', 'success')
    else:
        flash('Invalid status', 'danger')
    
    return redirect(url_for('admin_orders'))

@app.route('/admin/promotions')
@admin_required
def admin_promotions():
    promotions = Promotion.query.order_by(Promotion.valid_from.desc()).all()
    return render_template('admin/promotions.html',
                         title='Manage Promotions - Admin',
                         promotions=promotions)

@app.route('/admin/promotions/add', methods=['POST'])
@admin_required
def admin_add_promotion():
    code = request.form.get('code', '').strip().upper()
    description = request.form.get('description', '').strip()
    discount_type = request.form.get('discount_type', '')
    discount_value = request.form.get('discount_value', type=float)
    min_order = request.form.get('min_order', 0, type=float)
    max_usage = request.form.get('max_usage', 1, type=int)
    valid_to = request.form.get('valid_to', '')
    
    if not all([code, description, discount_type, discount_value]):
        flash('Please fill in all required fields', 'danger')
        return redirect(url_for('admin_promotions'))
    
    if Promotion.query.filter_by(code=code).first():
        flash('Promotion code already exists', 'danger')
        return redirect(url_for('admin_promotions'))
    
    promotion = Promotion(
        code=code,
        description=description,
        discount_type=discount_type,
        discount_value=discount_value,
        min_order=min_order,
        max_usage=max_usage
    )
    
    if valid_to:
        try:
            promotion.valid_to = datetime.strptime(valid_to, '%Y-%m-%d')
        except ValueError:
            flash('Invalid expiry date format', 'danger')
            return redirect(url_for('admin_promotions'))
    
    db.session.add(promotion)
    db.session.commit()
    
    flash(f'Promotion "{code}" added successfully!', 'success')
    return redirect(url_for('admin_promotions'))

@app.route('/admin/promotions/toggle/<int:promo_id>')
@admin_required
def admin_toggle_promotion(promo_id):
    promotion = Promotion.query.get_or_404(promo_id)
    promotion.active = not promotion.active
    db.session.commit()
    
    status = 'activated' if promotion.active else 'deactivated'
    flash(f'Promotion "{promotion.code}" {status}!', 'success')
    return redirect(url_for('admin_promotions'))

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html',
                         title='Manage Users - Admin',
                         users=users)

@app.route('/admin/users/toggle_admin/<int:user_id>')
@admin_required
def admin_toggle_user_admin(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent removing admin from current user
    if user.id == session['user_id'] and user.is_admin:
        flash('Cannot remove admin privileges from yourself', 'warning')
        return redirect(url_for('admin_users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    status = 'granted' if user.is_admin else 'removed'
    flash(f'Admin privileges {status} for {user.username}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/toggle_delivery/<int:user_id>')
@admin_required
def admin_toggle_user_delivery(user_id):
    user = User.query.get_or_404(user_id)
    user.is_delivery = not user.is_delivery
    db.session.commit()
    
    status = 'granted' if user.is_delivery else 'removed'
    flash(f'Delivery privileges {status} for {user.username}', 'success')
    return redirect(url_for('admin_users'))

# Delivery routes
@app.route('/delivery')
@delivery_required
def delivery_dashboard():
    delivery_person = User.query.get(session['user_id'])
    assigned_orders = Order.query.filter_by(
        delivery_person_id=delivery_person.id,
        status='out_for_delivery'
    ).all()
    
    completed_orders = Order.query.filter_by(
        delivery_person_id=delivery_person.id,
        status='delivered'
    ).order_by(Order.created_at.desc()).limit(10).all()
    
    return render_template('delivery/dashboard.html',
                         title='Delivery Dashboard',
                         assigned_orders=assigned_orders,
                         completed_orders=completed_orders)

# PWA routes
@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/sw.js')
def service_worker():
    return send_from_directory('static', 'sw.js')

# API routes for AJAX updates
@app.route('/api/cart_count')
def cart_count():
    count = 0
    if 'cart' in session:
        count = sum(item['quantity'] for item in session['cart'].values())
    return jsonify({'count': count})

@app.route('/api/validate_coupon', methods=['POST'])
def validate_coupon():
    data = request.get_json()
    code = data.get('code', '').strip().upper()
    subtotal = data.get('subtotal', 0)
    
    if not code:
        return jsonify({'valid': False, 'message': 'Please enter a coupon code'})
    
    promotion = Promotion.query.filter_by(code=code).first()
    
    if not promotion:
        return jsonify({'valid': False, 'message': 'Invalid coupon code'})
    
    if not promotion.is_valid():
        return jsonify({'valid': False, 'message': 'Coupon has expired or reached usage limit'})
    
    if subtotal < promotion.min_order:
        return jsonify({
            'valid': False, 
            'message': f'Minimum order amount is ₹{promotion.min_order:.2f}'
        })
    
    discount = promotion.calculate_discount(subtotal)
    
    return jsonify({
        'valid': True,
        'discount': discount,
        'message': f'Coupon applied! You save ₹{discount:.2f}'
    })

@app.route('/toggle_store_status', methods=['POST'])
@admin_required
def toggle_store_status():
    store_status['open'] = not store_status['open']
    status = 'open' if store_status['open'] else 'closed'
    return jsonify({'success': True, 'status': status, 'message': f'Store is now {status}'})

@app.route('/api/reorder', methods=['POST'])
def api_reorder():
    data = request.get_json()
    order_id = data.get('order_id')
    
    if not order_id:
        return jsonify({'success': False, 'message': 'Order ID is required'})
    
    # Find the order
    order = Order.query.filter_by(order_id=order_id).first()
    if not order:
        return jsonify({'success': False, 'message': 'Order not found'})
    
    # Get order items
    order_items = order.get_items()
    if not order_items:
        return jsonify({'success': False, 'message': 'No items found in order'})
    
    # Initialize cart if not exists
    if 'cart' not in session:
        session['cart'] = {}
    
    # Add items to cart
    cart = session['cart']
    items_added = 0
    
    for item_data in order_items:
        # Find the menu item to check if it's still available
        menu_item = MenuItem.query.get(int(item_data['id']))
        if menu_item and menu_item.in_stock:
            item_key = str(item_data['id'])
            
            if item_key in cart:
                cart[item_key]['quantity'] += item_data['quantity']
            else:
                cart[item_key] = {
                    'name': menu_item.name,
                    'price': menu_item.price,
                    'quantity': item_data['quantity'],
                    'emoji': menu_item.emoji
                }
            items_added += 1
    
    session['cart'] = cart
    session.modified = True
    
    if items_added == 0:
        return jsonify({'success': False, 'message': 'No items from your previous order are currently available'})
    elif items_added < len(order_items):
        return jsonify({'success': True, 'message': f'{items_added} items added to cart. Some items are no longer available.'})
    else:
        return jsonify({'success': True, 'message': f'All {items_added} items added to cart successfully!'})

@app.route('/generate_payment_qr/<order_id>')
def generate_payment_qr(order_id):
    import qrcode
    from io import BytesIO
    import base64
    
    order = Order.query.filter_by(order_id=order_id).first_or_404()
    
    # UPI payment string
    upi_id = "7903102794@ptsbi"
    merchant_name = "Biryani Club"
    amount = order.total
    
    # Create UPI payment URL
    upi_url = f"upi://pay?pa={upi_id}&pn={merchant_name}&am={amount}&cu=INR&tn=Payment for Order {order_id}"
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(upi_url)
    qr.make(fit=True)
    
    # Create QR code image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for embedding in HTML
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return jsonify({
        'qr_code': f"data:image/png;base64,{img_str}",
        'upi_url': upi_url,
        'amount': amount,
        'order_id': order_id
    })

@app.route('/generate_upi_qr')
def generate_upi_qr():
    import qrcode
    from io import BytesIO
    
    vpa = request.args.get('vpa', '7903102794@ptsbi')
    amount = request.args.get('amount', '0')
    order_id = request.args.get('order_id', '')
    
    # Create UPI payment URL
    upi_url = f"upi://pay?pa={vpa}&pn=Biryani Club&am={amount}&cu=INR&tn=Payment for Order {order_id}"
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=8,
        border=4,
    )
    qr.add_data(upi_url)
    qr.make(fit=True)
    
    # Create QR code image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Return image directly
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    from flask import Response
    return Response(buffer.getvalue(), mimetype='image/png')

@app.route('/get_order_details/<order_id>')
def get_order_details(order_id):
    order = Order.query.filter_by(order_id=order_id).first()
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    return jsonify({
        'order': {
            'order_id': order.order_id,
            'total': order.total,
            'status': order.status,
            'customer_name': order.customer_name,
            'payment_method': order.payment_method
        }
    })

def initialize_default_data():
    """Initialize default data if database is empty"""
    
    # Create admin user if none exists
    if not User.query.filter_by(is_admin=True).first():
        admin = User(
            username='admin',
            email='admin@biryaniclub.com',
            full_name='Admin User',
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
    
    # Create delivery user if none exists
    if not User.query.filter_by(is_delivery=True).first():
        delivery = User(
            username='delivery1',
            email='delivery@biryaniclub.com',
            full_name='Delivery Person',
            is_delivery=True
        )
        delivery.set_password('delivery123')
        db.session.add(delivery)
    
    # Add sample menu items if none exist
    if MenuItem.query.count() == 0:
        sample_items = [
            MenuItem(name='Chicken Biryani', category='Biryani', price=299, description='Aromatic basmati rice with tender chicken pieces', emoji='🍗', popularity=150),
            MenuItem(name='Mutton Biryani', category='Biryani', price=399, description='Rich and flavorful biryani with succulent mutton', emoji='🐏', popularity=120),
            MenuItem(name='Vegetable Biryani', category='Biryani', price=249, description='Garden fresh vegetables in fragrant basmati rice', emoji='🥬', popularity=80),
            MenuItem(name='Fish Biryani', category='Biryani', price=349, description='Fresh fish fillets with aromatic spices', emoji='🐟', popularity=70),
            MenuItem(name='Egg Biryani', category='Biryani', price=199, description='Boiled eggs in spiced rice', emoji='🥚', popularity=90),
            MenuItem(name='Chicken 65', category='Starters', price=179, description='Spicy and crispy chicken appetizer', emoji='🍗', popularity=100),
            MenuItem(name='Mutton Seekh Kebab', category='Starters', price=229, description='Grilled minced mutton skewers', emoji='🍢', popularity=85),
            MenuItem(name='Paneer Tikka', category='Starters', price=159, description='Grilled cottage cheese with spices', emoji='🧀', popularity=75),
            MenuItem(name='Fish Fry', category='Starters', price=199, description='Crispy fried fish with Indian spices', emoji='🐟', popularity=65),
            MenuItem(name='Raita', category='Sides', price=49, description='Cooling yogurt with cucumber and spices', emoji='🥒', popularity=110),
            MenuItem(name='Papad', category='Sides', price=29, description='Crispy lentil wafers', emoji='🥞', popularity=95),
            MenuItem(name='Pickle', category='Sides', price=19, description='Spicy and tangy Indian pickle', emoji='🥒', popularity=88),
            MenuItem(name='Gulab Jamun', category='Desserts', price=79, description='Sweet milk dumplings in sugar syrup', emoji='🍯', popularity=105),
            MenuItem(name='Kulfi', category='Desserts', price=69, description='Traditional Indian ice cream', emoji='🍦', popularity=92),
            MenuItem(name='Lassi', category='Beverages', price=59, description='Refreshing yogurt drink', emoji='🥤', popularity=130),
            MenuItem(name='Chai', category='Beverages', price=29, description='Traditional Indian tea', emoji='☕', popularity=140),
        ]
        
        for item in sample_items:
            db.session.add(item)
    
    # Add sample promotions if none exist
    if Promotion.query.count() == 0:
        sample_promotions = [
            Promotion(
                code='WELCOME10',
                description='Welcome offer - 10% off on first order',
                discount_type='percent',
                discount_value=10,
                min_order=200,
                max_usage=100,
                valid_to=datetime.utcnow() + timedelta(days=30)
            ),
            Promotion(
                code='BIRYANI50',
                description='₹50 off on orders above ₹500',
                discount_type='fixed',
                discount_value=50,
                min_order=500,
                max_usage=50,
                valid_to=datetime.utcnow() + timedelta(days=15)
            )
        ]
        
        for promo in sample_promotions:
            db.session.add(promo)
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error initializing default data: {e}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
