from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from db import get_db_connection  
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

app.secret_key = "change_this_secret_key"  
bcrypt = Bcrypt(app)


# ------------------ Helpers ------------------ #

def is_logged_in():
    return "user" in session

def login_required(view_func):
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper


# ------------------ Routes ------------------ #
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, password FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user and bcrypt.check_password_hash(user[1], password):
            session["user_id"] = user[0]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password", "danger")

    return render_template("login.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()

        if not username or not password:
            flash("Please fill all fields.", "warning")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # نتأكد ما فيه اسم مستخدم مكرر
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            db.close()
            flash("Username already exists.", "warning")
            return redirect(url_for("register"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, hashed_pw),
        )
        db.commit()
        cursor.close()
        db.close()

        flash("Account created. You can login now.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/dashboard")
@login_required
def dashboard():
    """
    صفحة الداشبورد الرئيسية
    """
    return render_template("dashboard.html", username=session.get("user"))


@app.route("/devices")
@login_required
def devices():
    """
    عرض قائمة الأجهزة
    """
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM devices")
    devs = cursor.fetchall()
    cursor.close()
    db.close()

    return render_template("devices.html", devices=devs)

@app.route("/add_device", methods=["GET", "POST"])
def add_device():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form["name"]
        device_type = request.form["type"]
        password = request.form["password"]

        conn = get_db_connection()
        cursor = conn.cursor()

     
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        cursor.execute(
            "INSERT INTO devices (name, type, password) VALUES (%s, %s, %s)",
            (name, device_type, hashed_password),
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash("Device added successfully!", "success")
        return redirect(url_for("devices"))

    return render_template("add_device.html")



@app.route("/edit_device/<int:device_id>", methods=["GET", "POST"])
@login_required
def edit_device(device_id):
    """
    تعديل بيانات جهاز
    """
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        type_ = request.form.get("type", "").strip()
        password = request.form.get("password", "").strip()

        cursor.execute(
            "UPDATE devices SET name=%s, type=%s, password=%s WHERE id=%s",
            (name, type_, password, device_id),
        )
        db.commit()
        cursor.close()
        db.close()
        flash("Device updated successfully.", "success")
        return redirect(url_for("devices"))

    # GET: نجيب بيانات الجهاز
    cursor.execute("SELECT * FROM devices WHERE id=%s", (device_id,))
    device = cursor.fetchone()
    cursor.close()
    db.close()

    if not device:
        flash("Device not found.", "danger")
        return redirect(url_for("devices"))

    return render_template("edit_device.html", device=device)


@app.route("/delete_device/<int:device_id>")
@login_required
def delete_device(device_id):
    """
    حذف جهاز
    """
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("DELETE FROM devices WHERE id=%s", (device_id,))
    db.commit()
    cursor.close()
    db.close()
    flash("Device deleted.", "info")
    return redirect(url_for("devices"))


@app.route("/tips")
@login_required
def tips():
    """
    صفحة نصائح الأمان
    """
    return render_template("tips.html")


@app.route("/logout")
def logout():
    """
    تسجيل خروج
    """
    session.pop("user", None)
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
