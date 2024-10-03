import getpass
from app import app, db  
from app import User 
from werkzeug.security import generate_password_hash 


with app.app_context():

    print("Create Superuser")
    first_name = input("First Name: ")
    last_name = input("Last Name: ")
    email = input("Email: ")
    password = getpass.getpass("Password: ")
    gender = input("Gender: ")
    age = int(input("Age: "))
    city = input("City: ")
    address = input("Address: ")
    phone_number = input("Phone Number: ")

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        print("Error: A user with this email already exists.")
    else:
        hashed_password = generate_password_hash(password)

        superuser = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password_hash=hashed_password,
            gender=gender,
            age=age,
            city=city,
            address=address,
            phone_number=phone_number,
            type='admin'      
            )

        db.session.add(superuser)
        db.session.commit()
        print(f"Superuser {first_name} {last_name} created successfully.")


        