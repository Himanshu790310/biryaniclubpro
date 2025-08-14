from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    emoji = db.Column(db.String(10))
    in_stock = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    popularity = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'price': self.price,
            'description': self.description,
            'emoji': self.emoji,
            'in_stock': self.in_stock,
            'popularity': self.popularity
        }

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    address = db.Column(db.Text)
    loyalty_points = db.Column(db.Integer, default=0)
    loyalty_tier = db.Column(db.String(20), default='bronze')
    is_admin = db.Column(db.Boolean, default=False)
    is_delivery = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_tier_color(self):
        colors = {
            'bronze': '#cd7f32',
            'silver': '#c0c0c0',
            'gold': '#ffd700'
        }
        return colors.get(self.loyalty_tier, '#cd7f32')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(20), unique=True, nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
    customer_phone = db.Column(db.String(15), nullable=False)
    customer_address = db.Column(db.Text, nullable=False)
    items_json = db.Column(db.Text, nullable=False)
    subtotal = db.Column(db.Float, nullable=False)
    discount = db.Column(db.Float, default=0)
    total = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='pending')
    coupon_code = db.Column(db.String(20))
    delivery_person_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    estimated_delivery = db.Column(db.DateTime)
    rating = db.Column(db.Integer)
    feedback = db.Column(db.Text)

    # Relationships
    delivery_person = db.relationship('User', foreign_keys=[delivery_person_id])
    customer = db.relationship('User', foreign_keys=[user_id])

    def get_items(self):
        try:
            return json.loads(self.items_json) if self.items_json else []
        except (json.JSONDecodeError, TypeError):
            return []

    def set_items(self, items):
        self.items_json = json.dumps(items)

    def get_status_color(self):
        colors = {
            'pending': 'warning',
            'confirmed': 'info',
            'preparing': 'primary',
            'out_for_delivery': 'secondary',
            'delivered': 'success',
            'cancelled': 'danger'
        }
        return colors.get(self.status, 'secondary')

class Promotion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    discount_type = db.Column(db.String(10), nullable=False)  # percent/fixed
    discount_value = db.Column(db.Float, nullable=False)
    min_order = db.Column(db.Float, default=0)
    valid_from = db.Column(db.DateTime, default=datetime.utcnow)
    valid_to = db.Column(db.DateTime)
    max_usage = db.Column(db.Integer, default=1)
    usage_count = db.Column(db.Integer, default=0)
    active = db.Column(db.Boolean, default=True)

    def is_valid(self):
        now = datetime.utcnow()
        return (self.active and 
                self.usage_count < self.max_usage and
                now >= self.valid_from and
                (self.valid_to is None or now <= self.valid_to))

    def calculate_discount(self, subtotal):
        if not self.is_valid() or subtotal < self.min_order:
            return 0
        
        if self.discount_type == 'percent':
            return subtotal * (self.discount_value / 100)
        else:
            return min(self.discount_value, subtotal)
