from flask import Flask, request, jsonify
from sqlalchemy import Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# Налаштування Flask
app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret-key"
jwt = JWTManager(app)

# Чорний список токенів
blacklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    return jwt_payload["jti"] in blacklist

# Налаштування SQLAlchemy
Base = declarative_base()
engine = create_engine('sqlite:///library.db')
Session = sessionmaker(bind=engine)
session = Session()

# Моделі SQLAlchemy
class Author(Base):
    __tablename__ = 'authors'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    books = relationship('Book', back_populates='author', cascade='all, delete-orphan')

class Book(Base):
    __tablename__ = 'books'
    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    author_id = Column(Integer, ForeignKey('authors.id'), nullable=False)
    author = relationship('Author', back_populates='books')

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)

# Створення таблиць
Base.metadata.create_all(engine)

# Маршрути для аутентифікації
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return {"message": "Invalid data, 'username' and 'password' are required"}, 400

    user = session.query(User).filter_by(username=data["username"]).first()
    if not user or user.password != data["password"]:
        return {"message": "Invalid credentials"}, 401

    access_token = create_access_token(identity=user.username)
    return {"access_token": access_token}, 200

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return {"message": "Invalid data, 'username' and 'password' are required"}, 400

    if session.query(User).filter_by(username=data["username"]).first():
        return {"message": "User already exists"}, 400

    new_user = User(username=data["username"], password=data["password"])
    session.add(new_user)
    session.commit()
    return {"message": f"User '{data['username']}' registered successfully."}, 201

@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    jti = get_jwt_identity()
    blacklist.add(jti)
    return {"message": "Successfully logged out."}, 200

# Захищені маршрути
@app.route("/authors", methods=["GET"])
@jwt_required()
def list_authors():
    authors = session.query(Author).all()
    return jsonify([{"id": author.id, "name": author.name} for author in authors])

@app.route("/authors", methods=["POST"])
@jwt_required()
def create_author():
    data = request.get_json()
    if not data or "name" not in data:
        return {"message": "Invalid data, 'name' is required"}, 400

    new_author = Author(name=data["name"])
    session.add(new_author)
    session.commit()
    return {"message": f"Author '{data['name']}' created successfully."}, 201

@app.route("/books", methods=["GET"])
@jwt_required()
def list_books():
    books = session.query(Book).all()
    return jsonify([{"id": book.id, "title": book.title, "author_id": book.author_id} for book in books])

@app.route("/books", methods=["POST"])
@jwt_required()
def create_book():
    data = request.get_json()
    if not data or "title" not in data or "author_id" not in data:
        return {"message": "Invalid data, 'title' and 'author_id' are required"}, 400

    author = session.query(Author).get(data["author_id"])
    if not author:
        return {"message": f"Author with ID {data['author_id']} not found."}, 404

    new_book = Book(title=data["title"], author=author)
    session.add(new_book)
    session.commit()
    return {"message": f"Book '{data['title']}' created successfully."}, 201

# Запуск сервера
if __name__ == "__main__":
    app.run(debug=True)
