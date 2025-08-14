# Biryani Club Deployment

## Deployment Instructions:

1. Upload this zip file to your deployment platform
2. Set the following environment variables:
   - DATABASE_URL: Your PostgreSQL database URL
   - SESSION_SECRET: A secure random string for session encryption
   - PORT: Will be set automatically by most platforms

3. The app will automatically:
   - Install dependencies from requirements.txt
   - Create database tables on first run
   - Initialize default menu items and admin user

## Default Admin Credentials:
- Email: admin@biryaniclub.com  
- Password: admin123

## Features:
- Restaurant menu management
- Order processing with UPI payments
- Admin dashboard
- Delivery tracking
- PWA support
- Store open/close functionality

For support, refer to the application documentation.
