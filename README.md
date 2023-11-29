# Flask User Login/Registeration App
This is a Flask application that demonstrates user registration and login.

## Target Features

Key Features:
User Registration:  
● Implement a registration endpoint that accepts user details (e.g., username,
password, mobile number).  
● Generate a secure OTP which should be valid for X minutes (settings should be
configurable) and send it to the provided mobile number.  
● Store user details securely, ensuring the password is hashed.  

User Login:  
● Create a login endpoint that accepts credentials (mobile number and OTP).  
● Verify the provided OTP against the stored OTP for the corresponding mobile
number.  
● If the OTP is valid, authenticate the user and provide access  

## Setup

1. Clone the repository
```bash
git clone https://github.com/vickytilotia/flask-user-registration.git
cd flask-user-authentication
```

2. Set up a virtual environment (optional but recommended):
```bash
python -m venv venv
# To activate virtualenv on windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```


3. Install the required packages:
```bash
pip install -r requirements.txt

```


4. Run the Flask application:
```bash
python app.py
```

## Usage  

● Register a new user by making a POST request to /register with the required JSON payload.  
● Login with the registered mobile number and OTP using a POST request to /login.   
● Access the protected route /protected by including the JWT token obtained during login in the Authorization header of a GET request.  


## Endpoints

POST /register

Register a new user. 

Required JSON payload:   
```
{"username": "your_username", "password": "your_password", "mobile_number": "your_mobile_number"} 
```

POST /login  

Login with mobile number and OTP.  

Required JSON payload:   
```
{"mobile_number": "your_mobile_number", "otp": "your_generated_otp"}  
```

GET /protected  

Access a protected route.  

Requires a valid JWT token obtained during login.  


## Security Measures  
● Passwords are hashed using bcrypt.  
● One-time passwords (OTPs) are generated using pyotp.  
● JSON Web Tokens (JWTs) are used for user authentication with the flask_jwt_extended extension.  
● Rate limiting is implemented using Flask-Limiter to prevent abuse.  
● Data validation is performed to ensure the correctness of user inputs.   
● SQLite database is used to store user data.  
● A secret key is used to sign JWTs.  
