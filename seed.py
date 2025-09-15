from app import db, create_app
from app.models import User
from faker import Faker

def seed_admin_user():
    admin_email = 'admin@thehexaa.com'
    admin_password = 'AdminPassword123!'  # Ensure this password meets your validation criteria

    existing_user = User.query.filter_by(email=admin_email).first()
    if existing_user:
        print('Admin user already exists.')
        return

    admin_user = User(
        email=admin_email,
        full_name='Admin User',  # Provide a valid full name
        role='Founder',  # Provide a valid role
        company_size='1001+'  # Provide a valid company size
    )
    admin_user.set_password(admin_password)
    admin_user.is_admin = True
    admin_user.email_verified = True

    db.session.add(admin_user)
    db.session.commit()
    print('Admin user created successfully.')

def insert_synthetic_data(num_users):
    faker = Faker()

    roles = ['Founder', 'Chief Revenue Officer', 'Head of Sales', 'Head of Enablement',
             'Director of Sales', 'Director of Enablement', 'Other']
    company_sizes = ['1-10', '11-50', '51-100', '100-500', '501-1000', '1001+']

    # Generate synthetic data for 'user' table
    for _ in range(num_users):
        email = faker.email()
        full_name = faker.name()
        role = faker.random.choice(roles)
        company_size = faker.random.choice(company_sizes)
        password = faker.password()
        
        user = User(
            email=email,
            full_name=full_name,
            role=role,
            company_size=company_size
        )
        user.set_password(password)
        user.is_admin = faker.boolean()
        user.email_verified = faker.boolean()
        db.session.add(user)
    
    db.session.commit()
    print(f"Inserted {num_users} rows into 'user' table.")

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        seed_admin_user()
        insert_synthetic_data(num_users=10)
