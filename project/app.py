from flask import Flask, render_template, redirect, request
import analyser

# Configure Flask application
app = Flask(__name__)

# Define template routes
@app.route("/")
def index():
    return render_template("index.html", current_page=request.path)

@app.route("/analyser", methods=["GET", "POST"])
def analyser():
    # Initialise final score
    score = 0

    return render_template("analyser.html", current_page=request.path)

@app.route("/simulator", methods=["GET", "POST"])
def simulator():
    return render_template("simulator.html", current_page=request.path) 

