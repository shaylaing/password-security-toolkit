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

    # Get inputted password from form submission
    password = request.form.get("password")

    # Ensure inputted password is not longer than 64 characters (server-side input validation)
    if len(password) > 64:
        # If password is too long, return early with suitable error message
        error_message = "400: Inputted password is too long."
        return render_template("analyser.html", current_page=request.path, error_message=error_message)

    return render_template("analyser.html", current_page=request.path)


@app.route("/simulator", methods=["GET", "POST"])
def simulator():
    return render_template("simulator.html", current_page=request.path) 
