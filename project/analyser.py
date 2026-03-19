from math import log2
import hashlib
import requests
import helpers

# Define every possible ASCII symbol/special character for entropy check and composition check
SYMBOLS_SET = {'!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
               ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~'}


# Define blocklist check function:
def blocklist_check(password: str) -> bool:
    # Declare match variable to track whether a match has been found
    match = False

    # Hash password with SHA-1 and store it
    password_hash = hashlib.sha1(password.encode()).hexdigest()

    # NOTE: .encode() converts password to UTF-8 as SHA-1 expects bytes, not a string. 
    # .hexdigest() converts the resulting binary hash to a readable hexadecimal string 
    # so that it is compatible with the Pwned API's hex format.

    # Store first five characters of password hash for k-anonymity suppression
    password_hash_prefix = password_hash[:5]

    # HTTP request header for Have I Been Pwned API query (polite API usage and helps avoid rate-limiting or filtering issues)
    headers = {
        "User-Agent": "password-security-toolkit"
    }

    # NOTE: We are providing the Have I Been Pwned API with identification by including 
    # this header in our request.

    # Query Have I Been Pwned password API for password hash prefix
    # Pwned API returns suffix-only results (first five hash characters not included)
    pwned_results = requests.get(
        f'https://api.pwnedpasswords.com/range/{password_hash_prefix}', timeout=5, headers=headers)

    # NOTE: Have I Been Pwned API documentation can be found at:
    # https://haveibeenpwned.com/api/v3#PwnedPasswords

    # Ensure Pwned API query is successful by checking for HTTP 200 status code
    if pwned_results.status_code == 200:
        # Convert Pwned suffix results to lowercase
        pwned_results_lower = pwned_results.text.lower()

        # Store Pwned suffix results with counts as list
        pwned_suffixes_and_counts = pwned_results_lower.splitlines()

        # Remove counts from Pwned suffix results:
        # Create new list to store suffix results without counts
        pwned_suffixes = []

        # Loop through each suffix in Pwned API results
        for suffix in pwned_suffixes_and_counts:
            # Find end of suffix
            end = suffix.index(":")

            # Store suffix without count in new list
            pwned_suffixes.append(suffix[:end])

        # Check if Pwned API query results match password hash:
        # Loop through each suffix in Pwned API results
        for suffix in pwned_suffixes:
            # Check if complete hash result (prefix + suffix) matches password hash
            if password_hash_prefix + suffix == password_hash:
                # Match found
                match = True
                return match

    # Check de-subbed versions of password if match is not found:
    if not match:
        # Create list containing all possible de-subbed versions of password
        desubbed_passwords = helpers.desubstitute(password)
           
        # Return False early if no substitutions were found for password (not vulnerable)
        if len(desubbed_passwords) == 1 and desubbed_passwords[0] == password.lower():
            return match
        
        # Limit the amount of desubbed password variants being queried against the API (limit = 200 variants) to prevent request hanging or timeouts caused by combinatorial explosion
        if len(desubbed_passwords) > 200:
            desubbed_passwords = desubbed_passwords[:200]
       
        # Loop through each possible de-subbed version of password
        for desubbed_password in desubbed_passwords:
            # Hash current de-subbed version of password with SHA-1
            desubbed_hash = hashlib.sha1(
                desubbed_password.encode()).hexdigest()

            # Store first five characters of de-subbed password hash for k-anonymity suppression (Pwned API returns suffix-only, meaning the first five hash characters are not included)
            desubbed_hash_prefix = desubbed_hash[:5]

            # Query Have I Been Pwned password API for current de-subbed password hash prefix
            try:
                pwned_desubbed_suffix_results = requests.get(
                f'https://api.pwnedpasswords.com/range/{desubbed_hash_prefix}', timeout=5, headers=headers)

            # Return False if API query failed/timed out
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                return False

            # Ensure Pwned API query is successful by checking for HTTP 200 status code
            if pwned_desubbed_suffix_results.status_code == 200:
                # Store Pwned suffix results with counts as list
                pwned_desubbed_suffixes_and_counts = pwned_desubbed_suffix_results.text.splitlines()

                # Remove counts from Pwned suffix results:
                # Create new list to store suffix results without counts
                pwned_desubbed_suffixes = []

                # Loop through each suffix in Pwned API results
                for suffix in pwned_desubbed_suffixes_and_counts:
                    # Find end of suffix
                    end = suffix.index(":")

                    # Store suffix without count in new list
                    pwned_desubbed_suffixes.append(suffix[:end])

                # Loop through each suffix in Pwned API results
                for suffix in pwned_desubbed_suffixes:
                    # Check if complete hash result (prefix + suffix) matches password hash
                    if desubbed_hash_prefix + suffix == desubbed_hash:
                        # Match found
                        match = True
                        return match
                    # Loop continues if match not found

    # NOTE: Have I Been Pwned's API returns a multi-line string of suffixes whose
    # prefix matches the prefix of the user's password hash. Therefore, we must use
    # .splitlines() to separate each suffix and add them to a list so that we can
    # iterate over them for the check. Likewise, we use .index() and slicing to remove
    # the counts that are paired with each suffix by the API.

    return match


# Define minimum length check function:
def min_length_check(password: str) -> tuple[int, int]:
    points = 0

    # Define default score cap
    score_cap = 100

    # Calculate and store length of password
    length = len(password)

    # Determine rewarded points and score cap:
    # Below 8 characters
    if length < 8:
        score_cap = 25
    # Between 8 - 11 characters
    elif 8 <= length < 12:
        score_cap = 60
        points += 20
    # Between 12 - 14 characters
    elif 12 <= length < 15:
        score_cap = 85
        points += 35
    # 15+ characters
    elif length >= 15:
        points += 50

    return points, score_cap


# Define entropy check function:
def entropy_check(password: str) -> tuple[int, int, int]:
    points = 0
    charset_range = 0

    # Define constants for each character type to be used when determining charset range
    NUMERICS = 10
    LOWERCASE = 26
    UPPERCASE = 26
    SYMBOLS = 32        # ASCII characters only

    # Calculate and store length of password
    length = len(password)

    # Determine charset range for entropy check:
    # Define boolean flag for each character type and set them to False by default
    has_numeric = False
    has_lower = False
    has_upper = False
    has_symbol = False

    # Detect which character types appear in password:
    # Loop through each character in password
    for char in password:
        # Check if character is numeric
        if char.isdigit() == True:
            has_numeric = True
        # Check if character is lowercase
        if char.islower() == True:
            has_lower = True
        # Check if character is uppercase
        if char.isupper() == True:
            has_upper = True
        # Check if character is symbol
        if char in SYMBOLS_SET:
            has_symbol = True
    
    # Calculate charset range:
    # Add numeric range to charset range if password contains an numeric character
    if has_numeric:
        charset_range += NUMERICS
    # Add lowercase range to charset range if password contains an lowercase character
    if has_lower:
        charset_range += LOWERCASE
    # Add uppercase range to charset range if password contains an uppercase character
    if has_upper:
        charset_range += UPPERCASE
    # Add symbol range to charset range if password contains a symbol
    if has_symbol:
        charset_range += SYMBOLS
    
    # Prevent charset range from being 0 by setting it to a default value of 1 
    if charset_range == 0:
        charset_range += 1
    
    # Calculate entropy
    entropy_bits = length * log2(charset_range)

    # Calculate total possible combinations an attacker would need to check to crack password
    possible_combinations = pow(2, entropy_bits)

    # Determine rewarded points:
    # Below 60 entropy bits
    if entropy_bits < 60:
        points += 0
    # Between 60 - 71 entropy bits
    elif 60 <= entropy_bits <= 71:
        points += 10
    # Between 72 - 80 entropy bits
    elif 72 <= entropy_bits <= 80:
        points += 20
    # Above 80 entropy bits
    elif entropy_bits > 80:
        points += 30

    return points, entropy_bits, possible_combinations


# Define composition check function:
def composition_check(password: str) -> int:
    points = 0

    # Detect which character types appear in password:
    # Define boolean flag for each character type and set them to False by default
    has_numeric = False
    has_lower = False
    has_upper = False
    has_symbol = False

    # Loop through each character in password
    for char in password:
        # Check if character is numeric
        if char.isdigit() == True:
            has_numeric = True
        # Check if character is lowercase
        if char.islower() == True:
            has_lower = True
        # Check if character is uppercase
        if char.isupper() == True:
            has_upper = True
        # Check if character is symbol
        if char in SYMBOLS_SET:
            has_symbol = True
    
    # Setup code for embedded check:
    has_embedded_digit_or_symbol = False

    # Ensure password is at least 3 characters long
    if len(password) >= 3:
        # Extract substring of only the embedded characters in password
        embedded_chars = password[1:len(password) - 1]

        # Detect if any numbers or symbols are embedded in password:
        # Loop through each character in embedded characters of password
        for char in embedded_chars:
            # Check if embedded char is numeric or a symbol
            if char.isnumeric() or char in SYMBOLS_SET:
                # Char is numeric or a symbol:
                has_embedded_digit_or_symbol = True

    # Check if password contains lowercase and uppercase characters AND embedded numbers or symbols
    if has_embedded_digit_or_symbol and has_lower and has_upper:
        points += 20
    # Check if password contains lowercase, uppercase, numbers, and symbols
    elif has_lower and has_upper and has_numeric and has_symbol:
        points += 15
    # Check if password contains lowercase, uppercase, and numeric characters
    elif has_lower and has_upper and has_numeric:
        points += 5
    # Check if password contains letters only or numbers only
    elif password.isalpha() or password.isdigit():
        points = 0

    return points


# Define pattern checks function:
def pattern_checks(password: str) -> int:
    deducted_points = 0
    sequential_chars = False
    keyboard_pattern = False
    repeated_chars = False

    # Define character sequence constants for sequential characters check
    SEQUENTIAL_LETTERS = "abcdefghijklmnopqrstuvwxyz"
    SEQUENTIAL_NUMBERS = "0123456789"

    # Define string set constant for keyboard patterns check
    KEYBOARD_PATTERNS = {"qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qweasd", "qazwsx", "wsxedc", "edcrfv", "rfvtgb", "tgbyhn", "yhnujm", "1qaz2wsx", "2wsx3edc", "3edc4rfv", "qwe", "asd", "zxc", "wer", "sdf", "xcv", "ert", "dfg", "cvb", "rty", "fgh", "vbn", "tyu", "ghj", "bnm", "yui", "hjk", "nmk", "uio", "jkl", "mkl", "iop", "klo", "pol", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890", "qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm"}

    # Check for sequential characters ('abc', '123', etc.) in password:
    # Loop through each character index in password 
    for i in range(len(password) - 2):
        # Access character in current iteration
        char = password[i]

        # Letter checks:
        # Ensure current character is a letter
        if char.isalpha():
            # Get index of character in letters list if current password character is a letter
            l = SEQUENTIAL_LETTERS.index(char.lower())

            # Ascending:
            # Prevent bound error by ensuring characters being checked don't exceed length of sequence constant
            if l + 2 < len(SEQUENTIAL_LETTERS):
                # Check if next character matches ascending letter sequence
                if password[i + 1].lower() == SEQUENTIAL_LETTERS[l + 1]:
                    # Check if next character also matches ascending letter sequence
                    if password[i + 2].lower() == SEQUENTIAL_LETTERS[l + 2]:
                        # Match found
                        sequential_chars = True
                        break
        
            # Descending:
            # Prevent underflow
            if l - 2 > -1:
                # Check if previous character matches descending letter sequence
                if password[i + 1].lower() == SEQUENTIAL_LETTERS[l - 1]:
                    # Check if previous character also matches descending letter sequence
                    if password[i + 2].lower() == SEQUENTIAL_LETTERS[l - 2]:
                        # Match found
                        sequential_chars = True
                        break

        # Number checks:
        # Ensure current character is a number
        if char.isdigit():
            # Get index of character in numbers list if current password character is a number
            n = SEQUENTIAL_NUMBERS.index(char)

            # Ascending:
            # Prevent bound error by ensuring characters being checked don't exceed length of sequence constant
            if n + 2 < len(SEQUENTIAL_NUMBERS):
                # Check if next character matches ascending number sequence
                if password[i + 1] == SEQUENTIAL_NUMBERS[n + 1]:
                    # Check if next character also matches ascending number sequence
                    if password[i + 2] == SEQUENTIAL_NUMBERS[n + 2]:
                        # Match found
                        sequential_chars = True
                        break

            # Descending:
            # Prevent underflow
            if n - 2 > -1:
                # Check if previous character matches descending number sequence
                if password[i + 1] == SEQUENTIAL_NUMBERS[n - 1]:
                    # Check if previous character also matches descending number sequence
                    if password[i + 2] == SEQUENTIAL_NUMBERS[n - 2]:
                        # Match found
                        sequential_chars = True
                        break

    # Check for keyboard patterns (including reversed) ('qwerty', 'asdfgh', etc.) in password:
    # Check every pattern and reversed pattern in the keyboard patterns constant for a substring match in password
    if any(pattern in password for pattern in KEYBOARD_PATTERNS) or any(pattern[::-1] in password for pattern in KEYBOARD_PATTERNS):
        # Match found
        keyboard_pattern = True
    
    # Check for repeated characters (3+ occurences) in password:
    # Loop through each character in password and fetch its index
    for i, char in enumerate(password):
        # Prevent overflow
        if i + 2 <= len(password) - 1:
            # Check if next two characters in password match current character
            if char == password[i + 1] and char == password[i + 2]:
                # Match found
                repeated_chars = True
                break

    # Determine deducted points for pattern checks:
    # Calculate how many pattern types appear in password
    pattern_match_count = sum([sequential_chars, keyboard_pattern, repeated_chars])

    # Determine deducted points:
    # No pattern types found
    if pattern_match_count == 0:
        return deducted_points
    # One pattern type found
    elif pattern_match_count == 1:
        deducted_points += 10
        return deducted_points
    # Two pattern types found
    elif pattern_match_count == 2:
        deducted_points += 25
        return deducted_points
    # Three pattern types found
    elif pattern_match_count == 3:
        deducted_points += 40
        return deducted_points

    # NOTE: We use sum() because, in Python, True has a value of 1 and False has a 
    # value of 0. So we can use sum() to total how many instances of True there are in 
    # a list of multiple variables.


# Define feedback creation function:
def feedback_creation(blocklist_check_result = False, min_length_check_points = 0, entropy_check_points = 0, composition_check_points = 0, pattern_check_points = 0) -> dict:
    # Create empty dictionary to store feedback messages to be returned
    messages = {}

    # Determine blocklist check message
    if blocklist_check_result == True:
        messages["blocklist_check"] = {
            "text": "Instant Fail: Password appears in blocklist (including de-substituted version).",
            "level": "bad"
        }
        
        # Only return this message if match is found
        return messages
    else:
        messages["blocklist_check"] = {
            "text": "Password does not appear in blocklist.",
            "level": "good"
        }

    # Determine minimum length check message
    if min_length_check_points == 0:
        messages["min_length_check"] = {
            "text": "Inadequate password length.",
            "level": "bad"
        }
    elif min_length_check_points == 20:
        messages["min_length_check"] = {
            "text": "Password length is okay.",
            "level": "okay"
        }
    elif min_length_check_points == 35:
        messages["min_length_check"] = {
            "text": "Password length is good.",
            "level": "good"
        }
    elif min_length_check_points == 50:
        messages["min_length_check"] = {
            "text": "Password length is great.",
            "level": "good"
        }
    
    # Determine entropy check message
    if entropy_check_points == 0:
        messages["entropy_check"] = {
            "text": "Password has very low entropy.",
            "level": "bad"
        }
    elif entropy_check_points == 10:
        messages["entropy_check"] = {
            "text": "Password has okay entropy.",
            "level": "okay"
        }
    elif entropy_check_points == 20:
        messages["entropy_check"] = {
            "text": "Password has good entropy.",
            "level": "good"
        }
    elif entropy_check_points == 30:
        messages["entropy_check"] = {
            "text": "Password has great entropy.",
            "level": "good"
        }

    # Determine composition check message
    if composition_check_points == 0:
        messages["composition_check"] = {
            "text": "Password has poor composition complexity.",
            "level": "bad"
        }
    elif composition_check_points == 5:
        messages["composition_check"] = {
            "text": "Password has okay composition complexity.",
            "level": "okay"
        }
    elif composition_check_points == 15:
        messages["composition_check"] = {
            "text": "Password has good composition complexity.",
            "level": "good"
        }
    elif composition_check_points == 20:
        messages["composition_check"] = {
            "text": "Password has great composition complexity.",
            "level": "good"
        }
    
    # Determine pattern check message
    if pattern_check_points == 0:
        messages["pattern_check"] = {
            "text": "Password contains no common patterns.",
            "level": "good"
        }
    elif pattern_check_points == 10:
        messages["pattern_check"] = {
            "text": "Password contains instances of one pattern type.",
            "level": "okay"
        }
    elif pattern_check_points == 25:
        messages["pattern_check"] = {
            "text": "Password contains instances of two pattern types.",
            "level": "bad"
        }
    elif pattern_check_points == 40:
        messages["pattern_check"] = {
            "text": "Password contains instances of three pattern types.",
            "level": "bad"
        }
    
    return messages

    # NOTE: Parameters for this function are given default values within its def statement. 
    # This is to ensure that each parameter still has a value when they are not included 
    # in the function call. Added 'level' functionality to indicate serverity of feedback 
    # when displayed in form.


# Define score colouring function:
def score_colour(score: int) -> str:
    # For scores between 0-49, colour final score red
    if score < 50:
        return "bad"
    # For scores between 50-74, colour final score amber
    elif 49 < score < 75:
        return "okay"
    # For scores between 75-100, colour final score green
    elif 84 < score <= 100:
        return "good"
