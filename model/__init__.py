from app import app
from model.user import *


with app.app_context():
    db.create_all()