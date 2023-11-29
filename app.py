# Import necessary libraries
import flask
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import pyotp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import SECRET_KEY as secret_key


# Initialize Flask app
app = Flask(__name__)

# Configure database connection
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user_data.db"
db = SQLAlchemy(app)


# Create user model
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    mobile_number = db.Column(db.String(12), unique=True, nullable=False)
    otp_secret = db.Column(db.String(200), nullable=False)
    registration_timestamp = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow()
    )


# Create the database tables
with app.app_context():
    db.create_all()

# Initialize JWT extension
app.config["SECRET_KEY"] = secret_key
app.config["JWT_ALGORITHM"] = "HS256"
jwt = JWTManager(app)

# Initialize Bcrypt
bcrypt = Bcrypt(app)


# Configure the Flask-Limiter extension
limiter = Limiter(
    get_remote_address, app=app, default_limits=["200 per day", "50 per hour"]
)


# User registration endpoint


@app.route("/register", methods=["POST"])
@limiter.limit("10 per minute")
def register():
    # Extract user data from request body
    user_data = request.get_json()
    username = user_data["username"] if "username" in user_data else None
    password = user_data["password"] if "password" in user_data else None
    mobile_number = user_data["mobile_number"] if "mobile_number" in user_data else None

    # Validate user data
    if not username or not password or not mobile_number:
        return jsonify({"error": "Missing required fields"}), 400

    # Username length should not be less than 6
    if len(username) < 6:
        return jsonify({"error": "Username length should not be less than 6 "}), 400

    # Password length should not be less than 8
    if len(password) < 8:
        return jsonify({"error": "Password length should not be less than 8"}), 400

    # Mobile number must be 10 digit long
    if len(mobile_number) != 10:
        return jsonify({"error": "Length of mobile_number must be 10 digit long"}), 400

    # If mobile_number must be integer
    if not mobile_number.isdigit():
        return jsonify({"error": "Mobile number must be integer"}), 400

    # Check if the username exists
    if username:
        user = User.query.filter_by(username=username).first()
        if user:
            return jsonify({"message": "Username already exists"}), 400

    # Check if the mobile number exists
    if mobile_number:
        user = User.query.filter_by(mobile_number=mobile_number).first()
        if user:
            return (jsonify({"message": "Mobile number already exists"}), 400)

    # Generate OTP
    otp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(otp_secret, interval=30)  # otp expires in 30 seconds
    otp = totp.now()

    # Hash password
    password_hash = bcrypt.generate_password_hash(password)

    # Create new user record
    new_user = User(
        username=username,
        password_hash=password_hash,
        mobile_number=mobile_number,
        otp_secret=otp_secret,
        registration_timestamp=datetime.utcnow(),
    )
    db.session.add(new_user)
    db.session.commit()

    # Send OTP (optional)
    print(f"OTP for {username} ({mobile_number}): {otp}")

    # Return success response
    return jsonify({"message": "User registration successful"}), 201


# User login endpoint
@app.route("/login", methods=["POST"])
@limiter.limit("15 per minute")
def login():
    # Extract credentials from request body
    credentials = request.get_json()
    mobile_number = (
        credentials["mobile_number"] if "mobile_number" in credentials else None
    )
    otp = credentials["otp"] if "otp" in credentials else None

    # Validate mobile number
    if not mobile_number or not otp:
        return jsonify({"error": "Missing required fields"}), 400

    if len(mobile_number) != 10:
        return jsonify({"error": "Invalid mobile number format"}), 400

    # Retrieve stored OTP for the corresponding mobile number
    user = User.query.filter_by(mobile_number=mobile_number).first()
    if not user:
        return jsonify({"error": "Mobile Number not registered"}), 400

    # Verify OTP
    stored_otp_secret = user.otp_secret  # Assuming otp_secret is stored in the database
    totp = pyotp.TOTP(stored_otp_secret)
    if not totp.verify(otp):
        return jsonify({"error": "Invalid OTP"}), 400

    # Generate access token
    access_token = create_access_token(identity=user.id)

    # Return success response with access token and user information
    return (
        jsonify(
            {
                "message": "Login successful",
                "access_token": access_token,
                "user_id": user.id,
                "username": user.username,
            }
        ),
        200,
    )


# Example protected route that requires a valid JWT
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user_id = get_jwt_identity()

    # Now you can use the user ID to retrieve user information from the database
    user = User.query.get(current_user_id)

    return (
        jsonify(
            {
                "message": "Access granted to protected route",
                "user_id": user.id,
                "username": user.username,
                "mobile_number": user.mobile_number,
            }
        ),
        200,
    )


if __name__ == "__main__":
    app.run(debug=True)
