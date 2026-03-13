from flask import Flask, render_template, redirect, request
from analyser import blocklist_check, min_length_check, entropy_check, composition_check, pattern_checks, feedback_creation
from simulator import brute_force_sim, dictionary_sim, hybrid_sim, rule_based_mutation_sim

# Configure Flask application
app = Flask(__name__)


# Define template routes:
@app.route("/")
def index():
    if request.method == "GET":
        return render_template("index.html", current_page=request.path)


@app.route("/analyser", methods=["GET", "POST"])
def analyser():
    if request.method == "GET":
        score = None
        return render_template("analyser.html", current_page=request.path, score=score)

    # Initialise final score
    score = 0

    # Check for POST request method (form submission)
    if request.method == "POST":
        # Input validation for form submission:
        # Get inputted password from form submission
        password = request.form.get("password")

        # Prevent empty password:
        if len(password) == 0:
            # Create error variable and set it to True
            empty_error = "Error 400: Password must be at least one character long."
            
            # Early return with error message
            return render_template("simulator.html", current_page=request.path, empty_error=empty_error)

        # Ensure inputted password is not longer than 64 characters (server-side input validation)
        if len(password) > 64:
            # If password is too long, return early with suitable error message
            length_error = "400: Inputted password is too long."
            return render_template("analyser.html", current_page=request.path, length_error=length_error)
        
        # Perform checks:
        # Blocklist check:
        # Perform check and store result
        blocklist_check_result = blocklist_check(password)

        # If blocklist check failed (return result is not a boolean expression), treat check as a pass
        if not isinstance(blocklist_check_result, bool):
            blocklist_check_result = False

        # If result of blocklist check is a fail, SKIP ALL OTHER CHECKS AND EARLY EXIT
        if blocklist_check_result == True:
            # Set final score to 0
            score = 0

            # Override all other checks and exit 
            return render_template("analyser.html", current_page=request.path, score=score, feedback=feedback_creation(blocklist_check_result))
        
        # NOTE: If match is found in blocklist check, then it is treated as an instant fail 
        # and overrides all other checks, returning a final score of 0. When a password appears
        # in the blocklist, it is certain that the password is extremely vulnerable and likely 
        # to be cracked.

        # Minimum length check:
        # Perform check and store result
        min_length_check_points, score_cap = min_length_check(password)        # Tuple unpacking to store multiple return values 

        # Add rewarded points for minimum length check to final score
        score += min_length_check_points

        # Initialise returned score cap as a constant
        SCORE_CAP = score_cap

        # NOTE: The minimum length check determines a score cap that limits the maximum score
        # the password can achieve. This design choice was made to reflect the importance 
        # the length of a password alone has on the hacker's ability to crack it.

        # Entropy check:
        # Perform check and store result
        entropy_check_points, entropy_bits, possible_combinations = entropy_check(password) 

        # Add rewarded points for entropy check to final score
        score += entropy_check_points

        # Round entropy bits to one decimal place
        entropy_bits = round(entropy_bits, 1)

        # Convert possible combinations to scientific notation with three significant figures (recommended by Claude for presentability)
        possible_combinations = f"{possible_combinations:.2E}"

        # Composition check:
        # Perform check and store result
        composition_check_points = composition_check(password)

        # Add rewarded points for composition check to final score
        score += composition_check_points

        # Pattern check: 
        # Perform check and store result
        pattern_checks_points = pattern_checks(password)

        # Subtract deducted points for patterns checks from final score
        score -= pattern_checks_points

        # Prevent negative final score
        score = max(score, 0)

        # Ensure final score complies with score cap
        score = min(score, SCORE_CAP)

        # Create feedback to be shown to the user
        feedback = feedback_creation(blocklist_check_result, min_length_check_points, entropy_check_points, composition_check_points, pattern_checks_points)

        return render_template("analyser.html", current_page=request.path, score=score, feedback=feedback, entropy_bits=entropy_bits, possible_combinations=possible_combinations)


@app.route("/simulator", methods=["GET", "POST"])
def simulator():
    if request.method == "GET":
        return render_template("simulator.html", current_page=request.path, submitted=False)
    
    if request.method == "POST":
        # Input validation for form submission:
        # Get inputted password from form submission
        password = request.form.get("password")

        # Prevent empty password:
        if len(password) == 0:
            # Create error variable and set it to True
            error = "Error 400: Password must be at least one character long."
            
            # Early return with error message
            return render_template("simulator.html", current_page=request.path, error=error, submitted=False)
        
        # Perform attack simulations:
        # Brute force simulation
        brute_force_times = brute_force_sim(password)

        # Dictionary simulation
        dictionary_times = dictionary_sim(password)

        # Hybrid simulation
        hybrid_times = hybrid_sim(password)

        # Rule-based mutation simulation
        rule_based_times = rule_based_mutation_sim(password)

        return render_template("simulator.html", current_page=request.path, brute_force_times=brute_force_times, dictionary_times=dictionary_times, hybrid_times=hybrid_times, rule_based_times=rule_based_times, submitted=True)
