from flask import Flask, render_template, redirect

# Configure Flask application
app = Flask(__name__)

# Define template routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyser")
def analyser():
    return render_template("analyser.html")

@app.route("/simulator")
def simulator():
    return render_template("simulator.html") 