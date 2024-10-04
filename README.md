# Library Web Application Backend

Welcome to the backend of the **Library Web Application**! This Flask-powered system is the backbone of a digital library that allows users to search for, borrow, and return books. It also provides comprehensive administrative tools for managing the library’s catalog and user base. With JWT-based authentication, security is a top priority, ensuring only authorized users can access specific features.

## Key Features

- **User Authentication**: Users can register, log in, and log out securely using JWT tokens.
- **Admin Capabilities**: Administrators can manage books, view loan histories, and update user information.
- **Book Borrowing/Returning**: Users can borrow books and return them, with full tracking of loan details.
- **Advanced Search**: Search for books by name, author, category, or publication year.
- **Token Refreshing**: Keep your session alive by refreshing access tokens using refresh tokens.
- **Admin-Only Access**: Restricted access for admin functions like adding or editing books.
- **Detailed Logging**: Track all key activities like login attempts, book management, and loan history.

## Technologies Used

- **Flask**: Python web framework to handle routing, requests, and more.
- **Flask-JWT-Extended**: Securing the application with JWT tokens.
- **Flask-SQLAlchemy**: ORM (Object-Relational Mapping) for managing the database.
- **SQLite**: Lightweight database used for development.
- **Flask-CORS**: To enable secure cross-origin requests between frontend and backend.
- **Logging**: Comprehensive logging with RotatingFileHandler for debugging and monitoring.

## Installation and Setup

Follow these steps to get the backend up and running on your local machine:

### 1. Clone the Repository

Start by cloning the repository from GitHub to your local machine:

```bash
git clone https://github.com/hadad890/flask_library_backend.git
cd library-backend
