from logging.handlers import RotatingFileHandler
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime,timedelta
from flask import Flask, logging, request, jsonify
from werkzeug.security import generate_password_hash ,check_password_hash
from flask_cors import CORS
from flask_jwt_extended.exceptions import NoAuthorizationError, RevokedTokenError
import logging
import jwt
from flask_jwt_extended import (
    JWTManager, get_jwt, jwt_required, create_access_token,
    jwt_required, create_refresh_token,
    get_jwt_identity, verify_jwt_in_request
)


app = Flask(__name__)
app.config['JWT_TOKEN_LOCATION'] = ['headers']  
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh'] 
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  
app.config['JWT_SECRET_KEY'] = 'your_secret_key' 
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'

db = SQLAlchemy(app)

CORS(app)
jwt = JWTManager(app)
blacklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_is_blacklisted(jwt_header, jwt_payload):
    jti = jwt_payload['jti']  
    return jti in blacklist  

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    type = db.Column(db.String(20), nullable=False, default='user')
    status = db.Column(db.String(30), nullable=False,default="Active") 
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(30), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    city = db.Column(db.String(30), nullable=False)
    address = db.Column(db.String(30), nullable=False)
    phone_number = db.Column(db.Integer, nullable=False)

    user_loans = db.relationship('Loan', back_populates='borrower', lazy=True)

class Book(db.Model):
    __tablename__ = 'books'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(30), unique=True, nullable=False)
    author = db.Column(db.String(30), nullable=False)
    category = db.Column(db.String(30), nullable=False)
    year_published = db.Column(db.Integer, nullable=False)
    summary = db.Column(db.String(300), nullable=False)
    type_borrow = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(30), nullable=False,default="Borrow") #
    img = db.Column(db.String(500), nullable=True)

    book_loans = db.relationship('Loan', back_populates='loaned_book', lazy=True)

class Loan(db.Model):
    __tablename__ = 'loans'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cust_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)
    status = db.Column(db.String(30), nullable=False,default="Borrow")
    loan_date = db.Column(db.DateTime,nullable=False) 
    return_date = db.Column(db.DateTime, nullable=False)

    borrower = db.relationship('User', back_populates='user_loans')
    loaned_book = db.relationship('Book', back_populates='book_loans')


@app.route('/register', methods=['POST'])
def register():
    data = request.json

    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    gender = data.get('gender')
    age = data.get('age')
    city = data.get('city')
    address = data.get('address')
    phone_number = data.get('phone_number')
   
    user_data = User(
    email=email,
    password_hash=generate_password_hash(password),
    first_name=first_name,
    last_name=last_name,
    gender=gender,
    age=age,
    city=city,
    address=address,
    phone_number=phone_number
    )

    if User.query.filter_by(email=email).first():
        app.logger.info(f"Attempting to register user with email: {email}")
        return jsonify({'error': 'Email already exists'}), 400
    
    db.session.add(user_data)
    db.session.commit()
    app.logger.info(f"User {email} registered successfully")

    return jsonify({'message': f"User {email} registered successfully"}), 201


#####################################################################################

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password_hash, password):
        app.logger.info(f"User {email} entered an invalid email or password")
        return jsonify({'error': 'Invalid email or password'}), 401
    
    if user.status != 'Active':
        app.logger.info(f"User {email} account is not active")
        return jsonify({'error': 'User account is not active'}), 403

    access_token = create_access_token(identity={'email': user.email, 'role': user.type, 'user_id': user.id})
    refresh_token = create_refresh_token(identity={'email': user.email, 'role': user.type, 'user_id': user.id})

    return jsonify({
        'message': 'Logged in successfully',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user_id': user.id,
        'user_name': f"{user.first_name} {user.last_name}"
    }), 200



#############################################################################################
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    token_data = get_jwt_identity()
    jti = get_jwt()["jti"]
    
    access_token_jti = jti
    refresh_token_jti = request.json.get('refresh_token_jti') 


    blacklist.add(access_token_jti)
    blacklist.add(refresh_token_jti)

    return jsonify({"message": "Successfully logged out"}), 200

#############################################################################################
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)  
def refresh():
    try:
        jwt_data = get_jwt()  
        app.logger.info(f"JWT data for refresh token: {jwt_data}")

        
        current_user = get_jwt_identity()
        app.logger.info(f"Refreshing token for user: {current_user}")

       
        new_access_token = create_access_token(identity=current_user)
        new_refresh_token = create_refresh_token(identity=current_user)

    
        return jsonify({
            'message': 'Access token refreshed',
            'access_token': new_access_token,
            'refresh_token': new_refresh_token
        }), 200
    except NoAuthorizationError:
        app.logger.info("No valid refresh token found")
        return jsonify({'error': 'No valid refresh token found'}), 401
    except RevokedTokenError:
        app.logger.info("Refresh token has been revoked")
        return jsonify({'error': 'Refresh token revoked'}), 401
    except Exception as e:
        app.logger.info(f"Error refreshing token: {str(e)}")
        return jsonify({'error': 'Failed to refresh token'}), 401


#############################################################################################

@app.route('/validate-token', methods=['POST'])
def validate_token():
    try:
        verify_jwt_in_request() 
        user_identity = get_jwt_identity()  
        app.logger.info(f"Token is valid, user: {user_identity}")
        return jsonify({'message': 'Token is valid', 'user': user_identity}), 200
    except Exception as e:
        app.logger.info(f"Invalid or expired token: {str(e)}")
        return jsonify({'error': 'Invalid or expired token'}), 401



#############################################################################################


@app.route('/add_books', methods=['POST'])
@jwt_required() 
def add_books():

    token_data = get_jwt_identity()
    user_role = token_data.get('role')

    if user_role != 'admin':
        app.logger.info(f"You do not have access to this resource{token_data}")
        return jsonify({"error": "You do not have access to this resource"}), 403 
    
    data = request.json

    name = data.get('name')
    author = data.get('author')
    category = data.get('category')
    year_published = data.get('year_published')
    summary = data.get('summary')
    type_borrow = data.get('type_borrow')
    img = data.get('img')

    data_book = Book(
    name = name,
    author = author,
    category = category,
    year_published = year_published,
    summary = summary, 
    type_borrow = type_borrow,
    img = img
    )



    if not name or not author or not category or not year_published or not summary or not type_borrow:
        return jsonify({'error': 'Missing required fields'}), 400

    if Book.query.filter_by(name=name).first():
        return jsonify({'error': 'Book already exists'}), 400

    db.session.add(data_book)
    db.session.commit()
  

    return jsonify({'message': f"Book {name} add successfully"})

#############################################################################################
@app.route('/borrow', methods=['POST'])
@jwt_required()
def borrow():
    token_data = get_jwt_identity()
    app.logger.info(f"Access token identity in /borrow: {token_data}")
    
    data = request.json
    cust_id = data.get('cust_id')
    book_id = data.get('book_id')

    user = User.query.filter_by(id=cust_id).first()
    if not user:
        return jsonify({'error': 'User not exists'}), 400

    book = Book.query.filter_by(id=book_id).first()
    if not book:
        return jsonify({'error': 'Book not exists'}), 400

    if book.status == "Borrow":
         book.status = "Unavailable"
    else:
        return jsonify({'message':'Book is already borrowed'}), 400
    
    

    loan_date = datetime.now().replace(microsecond=0)

    if book.type_borrow == 1:
        return_date = loan_date + timedelta(days=10)
    elif book.type_borrow == 2:
         return_date = loan_date + timedelta(days=5)
    else:
         return_date = loan_date + timedelta(days=2)
   

    data_loan = Loan(
        cust_id=cust_id,
        book_id=book_id,
        loan_date=loan_date,
        return_date=return_date,
        status="Borrow"

    )

    db.session.add(data_loan)
    db.session.commit()
    app.logger.info(f"Borrows uccessfully: {token_data}")

    return jsonify({'user_name': f"{user.first_name} {user.last_name}", 'loan_date': loan_date, 'return_date': return_date })








#################################################################################################################

@app.route('/view', methods=['GET'])
def view():
    books = Book.query.all()

    books_list = []
    for book in books:
        books_list.append({
            'id': book.id,
            'name': book.name,
            'author': book.author,
            'category': book.category,
            'year_published': book.year_published,
            'summary': book.summary,
            'type_borrow': book.type_borrow,
            'status': book.status,
            'img': book.img
        })
    app.logger.info(f"view loaded")
    return jsonify(books_list), 200

####################################################################################################################

# selc = selction kw = key word to serch 

@app.route('/search/<selc>/<kw>', methods=['GET'])
def search_books(selc, kw):
    valid_columns = ['name', 'author', 'category', 'year_published']

   
    if selc not in valid_columns:
        app.logger.info("error Invalid search field")
        return jsonify({"error": "Invalid search field"}), 400

    books = Book.query.filter(getattr(Book, selc).ilike(f"%{kw}%")).all()

    if books:
        return jsonify([{
            'id': book.id,
            'name': book.name,
            'author': book.author,
            'category': book.category,
            'year_published': book.year_published,
            'summary': book.summary,
            'type_borrow': book.type_borrow,
            'status': book.status,
            'img': book.img
        } for book in books]), 200
    else:
        app.logger.info(f"Search uccessfully load")
        return jsonify({"message": "No books found"}), 400

####################################################################################################################

@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    token_data = get_jwt_identity() 
    app.logger.info(f"Token Data: {token_data}")  

    user_id = token_data.get('user_id') if isinstance(token_data, dict) else token_data
    app.logger.info(f"User ID: {user_id}") 

    if not user_id:
        app.logger.info('error User ID is missing or invalid')
        return jsonify({'error': 'User ID is missing or invalid'}), 400

    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    borrowed_books_data = []
    
  
    for loan in user.user_loans:
        if loan.status == "Borrow":  
            book_data = {
                'id':loan.loaned_book.id,
                'title': loan.loaned_book.name,
                'author': loan.loaned_book.author,
                'img': loan.loaned_book.img,  
                'borrow_date': loan.loan_date.strftime('%Y-%m-%d'),
                'return_date': loan.return_date.strftime('%Y-%m-%d') if loan.return_date else None
            }
            borrowed_books_data.append(book_data)
    app.logger.info(f'Profile load {token_data}')

    
    return jsonify({
        'username': f"{user.first_name} {user.last_name}",
        'borrowed_books': borrowed_books_data
    }), 200


####################################################################################################################

@app.route('/return-book', methods=['POST'])
@jwt_required()
def return_book():
    token_data = get_jwt_identity()
    app.logger.info(f"Incoming request data by: {token_data}")

    data = request.get_json()
    book_id = data.get('book_id')
    
    if not book_id:
        return jsonify({'error': 'Book ID is missing'}), 400

    user_id = get_jwt_identity().get('user_id')
    
    app.logger.info(f"User ID: {user_id}, Book ID: {book_id}")

    loan = Loan.query.filter_by(cust_id=user_id, book_id=book_id, status="Borrow").first()
    
    if not loan:
        return jsonify({'error': 'Loan record not found or already returned'}), 400

    loan.status = "Returned"
    loan.return_date = datetime.now()

    book = Book.query.get(book_id)
    book.status = "Borrow"

    db.session.commit()
    app.logger.info(f'Book returned successfully by: {token_data}')

    return jsonify({'message': 'Book returned successfully'}), 200
####################################################################################################################

@app.route('/book_edit/<int:book_id>', methods=['POST'])
@jwt_required() 
def book_edit(book_id):

    token_data = get_jwt_identity()
    user_role = token_data.get('role')

    if user_role != 'admin':
        app.logger.info(f"You do not have access to this resource {token_data}")
        return jsonify({"error": "You do not have access to this resource"}), 403
    

    book = Book.query.get(book_id)
    if not book:
        return jsonify({"error": "Book not found"}), 404
    

    data = request.json

    book.name = data.get('name', book.name)
    book.author = data.get('author', book.author)
    book.category = data.get('category', book.category)
    book.year_published = data.get('year_published', book.year_published)
    book.summary = data.get('summary', book.summary)
    book.type_borrow = data.get('type_borrow', book.type_borrow)
    book.status = data.get('status', book.status)
    book.img = data.get('img', book.img)

    try:
        db.session.commit()
        app.logger.info(f"Book {book.name} updated successfully! by: {token_data}")
        return jsonify({"message": f"Book '{book.name}' updated successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to update book", "details": str(e)}), 500

####################################################################################################################

@app.route('/users', methods=['GET', 'POST'])
@jwt_required()
def users():
    token_data = get_jwt_identity()
    user_role = token_data.get('role')
    app.logger.info(f"user end point rquest by {token_data}")

    if user_role != 'admin':
        return jsonify({"error": "You do not have access to this resource"}), 403


    if request.method == 'GET':
        users = User.query.all()
        users_list = []
        for user in users:
            users_list.append({
                'id': user.id,
                'email': user.email,
                'type': user.type,
                'status': user.status,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'gender': user.gender,
                'age': user.age,
                'city': user.city,
                'address': user.address,
                'phone_number': user.phone_number
            })
        return jsonify(users_list), 200

    elif request.method == 'POST':
        data = request.json
        user_id = data.get('id')  
        
        if not user_id:
            return jsonify({"error": "User ID is required to update"}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404

      
        user.first_name = data.get('first_name', user.first_name)
        user.last_name = data.get('last_name', user.last_name)
        user.gender = data.get('gender', user.gender)
        user.age = data.get('age', user.age)
        user.city = data.get('city', user.city)
        user.address = data.get('address', user.address)
        user.phone_number = data.get('phone_number', user.phone_number)
        user.status = data.get('status', user.status)

        try:
            db.session.commit()
            app.logger.info(f"User {user.first_name} {user.last_name} updated successfully! by {token_data}")
            return jsonify({"message": f"User '{user.first_name} {user.last_name}' updated successfully!"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": "Failed to update user", "details": str(e)}), 500

####################################################################################################################
@app.route('/aprove', methods=['GET'])
@jwt_required()
def admin_check():
    token_data = get_jwt_identity()
    user_role = token_data.get('role')
    app.logger.info(f"user try log admin page  {token_data}")

    if user_role == 'admin':
        app.logger.info(f"user identfid as admin {token_data}")
        return jsonify({"message": "Access granted"}), 200
    else:
        app.logger.info(f"Access denied to admin page {token_data}")
        return jsonify({"error": "Access denied. Admin only."}), 403
    

####################################################################################################################
@app.route('/view_loans', methods=['GET'])
@jwt_required()
def view_loans():
    token_data = get_jwt_identity()
    user_role = token_data.get('role')
    app.logger.info(f"user end point rquest by {token_data}")

    if user_role != 'admin':
        return jsonify({"error": "You do not have access to this resource"}), 403

    loans = Loan.query.all()  
    loans_list = []
    for loan in loans:
        loans_list.append({
            'loan_id': loan.id,
            'book_name': loan.loaned_book.name, 
            'book_author': loan.loaned_book.author,
            'book_category': loan.loaned_book.category,
            'loan_date': loan.loan_date.strftime('%Y-%m-%d'), 
            'return_date': loan.return_date.strftime('%Y-%m-%d'),
            'loan_status': loan.status,
            'user_email': loan.borrower.email  
        })

    app.logger.info("Loans view loaded successfully")
    return jsonify(loans_list), 200
####################################################################################################################

if __name__ == '__main__':
    log_file_handler = RotatingFileHandler('app.log', maxBytes=1024 * 1024, backupCount=5)
    log_file_handler.setLevel(logging.INFO) 
    log_file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))

    app.logger.addHandler(log_file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    app.logger.addHandler(console_handler)
    app.logger.info("Starting Flask app...")

    with app.app_context():
        db.create_all()

    app.run(debug=True)







