from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import dynaconf
import jose
from jose import jwt
from sqlalchemy import asc, desc
from flask import send_from_directory

app = Flask(__name__)
db = SQLAlchemy()
settings = dynaconf.FlaskDynaconf(
    app,
    settings_files=["settings.toml", ".secrets.toml"],
)

db.init_app(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return "<User %r>" % self.username

with app.app_context():
    db.create_all()

def generate_jwt(payload):
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm=app.config["ALGORITHM"])
    return token

def verify_jwt(token):
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=[app.config["ALGORITHM"]])
        return payload
    except jose.exceptions.JWTError:
        return None

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if data.get('username') is None or len(data['username']) == 0:
        return jsonify({'message': 'Username vazio'}), 422
    if data.get('email') is None or len(data['email']) == 0:
        return jsonify({'message': 'Email vazio'}), 422
    if data.get('password') is None or len(data['password']) == 0:
        return jsonify({'message': 'Password vazio'}), 422

    new_user = User(
        username=data['username'],
        email=data['email'],
        password=data['password']
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'id': new_user.id, 'username': new_user.username, 'email': new_user.email}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if data.get('username') is None or len(data['username']) == 0:
        return jsonify({'message': 'Username vazio'}), 422
    if data.get('password') is None or len(data['password']) == 0:
        return jsonify({'message': 'Password vazio'}), 422

    user = User.query.filter_by(username=data['username'], password=data['password']).first()
    if user:
        payload = {
            'exp': datetime.now() + timedelta(minutes=30),
            'iat': datetime.now(),
            'sub': str(user.id)
        }
        token = generate_jwt(payload)
        user_json = {'id': user.id, 'username': user.username, 'email': user.email}
        return jsonify({'token': token, 'user': user_json}), 201
    return jsonify({'message': 'Invalid username or password'}), 422




@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    authorization = request.headers.get("Authorization")
    token = authorization.split(" ")[1] if authorization else None
    if not token:
        return jsonify({"message": "Token está faltando"}), 401
    payload = verify_jwt(token)
    if not payload:
        return jsonify({"message": "Token inválido"}), 401
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "Usuário não encontrado"}), 404
    return jsonify({"id": user.id, "username": user.username, "email": user.email})




@app.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    authorization = request.headers.get("Authorization")
    token = authorization.split(" ")[1] if authorization else None
    if not token:
        return jsonify({"message": "Token faltando"}), 401
    payload = verify_jwt(token)
    if not payload:
        return jsonify({"message": "Token inválido"}), 401
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "Usuário não encontrado"}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "Usuário deletado com sucesso"})


'''DOESN'T WORKKKK AND I DON'T KNOW WHYYYY    X(

@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    authorization = request.headers.get('Authorization')
    if not authorization:
        return jsonify({'message': 'Token faltando'}), 401

    token = authorization.split(' ')[1]
    payload = verify_jwt(token)
    if not payload:
        return jsonify({'message': 'Token inválido'}), 401

    data = request.get_json()
    if data.get('username') is None or len(data['username']) == 0:
        return jsonify({'message': 'Username vazio'}), 422
    if data.get('email') is None or len(data['email']) == 0:
        return jsonify({'message': 'Email vazio'}), 422

    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'Usuário não encontrado'}), 404

    user.username = data['username']
    user.email = data['email']
    db.session.flush()
    db.session.commit()
    return jsonify({'id': user.id, 'username': user.username, 'email': user.email})

traAAAAAAAAshh'''
#(Foi mal pelos comments exagerados, é que realmente me estressei um pouco com isso, pela falta de tempo kk)
@app.route('/')
def home():
    return send_from_directory('static', 'index.html')