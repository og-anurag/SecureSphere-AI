from flask import Flask,render_template,request,redirect
from db import database
dbo=database()
app=Flask(__name__)
@app.route("/")
def index():
    return render_template("login.html")
@app.route("/register")
def register():
    return render_template("register.html")
@app.route("/perform_registration",methods=['post'])
def perform_registration():
    name=request.form.get("name")
    email=request.form.get("email")
    password=request.form.get("password")
    response=dbo.insert(name,email,password)
    if response:
        return render_template(
            'login.html',
            message="Registration successful! Kindly proceed to login page"
        )
    else:
        return render_template(
            'register.html',
            error_message="User already exists."
        )
@app.route("/perform_login",methods=['POST'])
def perform_login():
    email=request.form.get("users_email")
    password=request.form.get("users_password")
    response=dbo.perform_login(email,password)
    if response:
        return redirect("/index")
    else:
        return render_template("login.html",error_message="Incorrect Email/Password")
@app.route("/index")
def main_page():
    return render_template("index.html")

app.run(debug=True)