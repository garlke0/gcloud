import os
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, flash
from flask import session
from security import verify_password
from models import db, User
from security import hash_password

load_dotenv("../.env")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

db.init_app(app)


def get_client_ip():
    """Trust proxy headers only when we know a proxy set them."""
    if os.environ.get("TRUST_PROXY") == "1":
        return request.headers.get("CF-Connecting-IP") or request.remote_addr
    return request.remote_addr


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    # 1. Validate bounds -- before anything expensive runs.
    if len(username) < 3 or len(username) > 64:
        flash("Username must be 3-64 characters.")
        return render_template("register.html"), 400

    if len(password) < 10 or len(password) > 128:
        flash("Password must be 10-128 characters.")
        return render_template("register.html"), 400

    # 2. Availability check. Generic message -- no username enumeration.
    if User.query.filter_by(username=username).first():
        flash("That username is not available.")
        return render_template("register.html"), 409

    # 3. Argon2id. The expensive step, reached only by valid input.
    password_hash = hash_password(password)

    # 4. Three fields set. The other seven fill themselves.
    user = User(
        username=username,
        password_hash=password_hash,
        registration_ip=get_client_ip(),
    )
    db.session.add(user)
    db.session.commit()

    # 5. Redirect, not render -- see below.
    flash("Account created. Sign in below.")
    return redirect(url_for("register"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    user = User.query.filter_by(username=username).first()

    if user and user.status == "deleted":
        flash("This account is no longer available.")
        return render_template("login.html"), 403

    if user and user.status == "banned":
        flash("This account has been suspended.")
        return render_template("login.html"), 403

    if not user or not verify_password(user.password_hash, password):
        flash("Incorrect username or password.")
        return render_template("login.html"), 401

    user.last_login_ip = get_client_ip()
    db.session.commit()

    session["user_id"] = user.id
    session["username"] = user.username
    session["role"] = user.role

    return redirect(url_for("welcome"))
@app.route("/welcome")
def welcome():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return render_template("welcome.html", username=session["username"])


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))
if __name__ == "__main__":
    app.run(debug=True, port=5000)