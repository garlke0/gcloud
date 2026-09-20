import os
from dotenv import load_dotenv
from flask import Flask
from models import db

load_dotenv("../.env")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]

db.init_app(app)

with app.app_context():
    db.create_all()
    print("tables created")