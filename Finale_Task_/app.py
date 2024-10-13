import os
import secrets
from datetime import timedelta
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask application
app = Flask(__name__)

# Configuration for the SQLite database
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'database.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)  # Set token expiry to 24 hour

# Initialize database and JWT
db = SQLAlchemy(app)
jwt = JWTManager(app)

# User model
class User(db.Model):
    """Model for users data""" 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)  # Add username field
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default='user')  # user/admin

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

def create_db():
    """Create the database and tables."""
    try:
        with app.app_context():
            # Remove existing tables
            #db.drop_all()
            # Create new tables
            db.create_all()

            # Check if admin user already exists
            existing_admin = User.query.filter_by(email='admin@example.com').first()
            if not existing_admin:
                new_admin = User(
                    username='admin',
                    first_name='Admin',
                    last_name='User',
                    email='admin@example.com',
                    phone_number='0123456789',
                    role='admin'
                )
                new_admin.set_password('securepassword')  # Set a secure password

                db.session.add(new_admin)
                db.session.commit()
                print("Admin user created.")
            else:
                print("Admin user already exists.")
    except Exception as e:
        print(f"An error while creating the database: {e}")

@app.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.json
    if not data or not all(k in data for k in ("username", "first_name", "last_name", "email", "phone_number", "password")):
        return jsonify({"message": "Missing data!"}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Email already exists!"}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username already exists!"}), 400

    new_user = User(
        username=data['username'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        email=data['email'],
        phone_number=data['phone_number'],
        role=data.get('role', 'user')
    )
    # Hash the password
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()
    print(f"User {new_user.email} registered successfully with hashed password {new_user.password}")
    return jsonify({"message": "User registered successfully!"}), 201

@app.route('/login', methods=['POST'])
def login():
    """Login a user."""
    data = request.get_json()
    if not data or not all(k in data for k in ("email", "password")):
        return jsonify({"message": "Missing email or password!"}), 400

    user = User.query.filter_by(email=data.get('email')).first()
    if user:
        print(f"User {user.email} found with hashed password {user.password}")
    else:
        print(f"User with email {data.get('email')} not found")

    if user and user.check_password(data.get('password')):
        access_token = create_access_token(identity={'email': user.email, 'is_admin': user.role == 'admin'})
        return jsonify({"message": "Login successful", "access_token": access_token}), 200
    return jsonify({"message": "Bad email or password"}), 401

@app.route('/admin_only_page', methods=['GET'])
@jwt_required()
def admin_only_page():
    """Access the admin-only page."""
    current_user = get_jwt_identity()
    if not current_user.get('is_admin', False):
        return jsonify({"message": "Admins only!"}), 403

    user = User.query.filter_by(email=current_user['email']).first()
    return jsonify({"message": f"Hello admin {user.username}!"}), 200

@app.route('/all_users', methods=['GET'])
@jwt_required()
def all_users():
    """Get all users."""
    users = User.query.all()
    user_list = [f"hello_{user.username}" for user in users]
    return jsonify(user_list), 200

@app.route('/create_admin', methods=['POST'])
@jwt_required()
def create_admin():
    """Create a new admin user."""
    current_user = get_jwt_identity()
    if not current_user.get('is_admin', False):
        return jsonify({"message": "Admins only!"}), 403

    data = request.get_json()
    if not data or not all(k in data for k in ("username", "first_name", "last_name", "email", "phone_number", "password")):
        return jsonify({"message": "Missing data!"}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "User already exists!"}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username already exists!"}), 400

    new_admin = User(
        username=data['username'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        email=data['email'],
        phone_number=data['phone_number'],
        role='admin'
    )
    new_admin.set_password(data['password'])

    db.session.add(new_admin)
    db.session.commit()

    return jsonify({"message": "Admin user created successfully!"}), 201

@app.route('/visitor', methods=['GET'])
def visitor():
    """Access the visitor page."""
    return jsonify({"message": "Hello Visitor!"}), 200

if __name__ == '__main__':
    # the database is created before starting the app
    create_db()
    app.run(debug=True)

