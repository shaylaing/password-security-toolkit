from math import log2
import hashlib
import requests

# Define every possible ASCII symbol/special character for entropy check and composition check
SYMBOLS_SET = {'!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
               ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~'}


# Define dict of commonly substituted characters and their singular substitutions (a.k.a. Leet Speak) for blocklist check
COMMON_SUBSTITUTIONS = {
    "a": ["@", "4", "^"],
    "b": ["8", "6", "ß"],
    "c": ["©", "¢", "<", "[", "(", "{"],
    "d": [")", "?"],
    "e": ["3", "&", "€", "ë"],
    "f": ["ƒ"],
    "g": ["6", "9", "&"],
    "h": ["#"],
    "i": ["1", "!", "¡", "|", "]"],
    "j": ["]", "¿"],
    "k": ["X"],
    "l": ["|", "1", "£", "¬"],
    "m": [],
    "n": [],
    "o": ["0", "°"],
    "p": ["¶", "9"],
    "q": ["9"],
    "r": ["2", "®"],
    "s": ["5", "$", "§", "z"],
    "t": ["7", "+", "†"],
    "u": ["µ", "v"],
    "v": ["^"],
    "w": [],
    "x": ["%", "*"],
    "y": ["¥", "J", "j"],
    "z": ["2", "%"]
}


# Reverse mapping for desubstitute function (suggested by Claude to allow for fast O(1) value lookup on the COMMON_SUBSTITUTIONS dict)
# Initialise empty dict for reverse map
common_substitutions_reverse_map = {}
# Take each key (real char) and its list of substitutions (values) (.items prevents default key-only iteration over dict)
for key, vals in COMMON_SUBSTITUTIONS.items():
    # Take each value in values (subbed chars)
    for val in vals:        
        # Register value (subbed char) as key to reverse map with an empty list as its value, and append each matching real char to that key (subbed char)
        common_substitutions_reverse_map.setdefault(val, []).append(key)

# Dictionary lookup is slow as it searches via keys by default. Reverse
# mapping enables us to flip the dictionary around so that we treat its values
# as keys instead so that we can search via its values and speed up the process
# of searching the dictionary. Provides improvement from O(n) per character to
# O(1) per character.


# Define function to generate all possible original passwords by reversing character substitutions (used in blocklist check)
def desubstitute(password: str) -> list[str]:
    # Initialise list with empty string to act as starting base for building combinations
    desubbed_possibilities = [""]

    #  Loop through each character in the password
    for char in password:
        # Ensure character is lowercase before checking against dict
        char = char.lower()

        # Check for all possible original characters this current character could represent
        if char in common_substitutions_reverse_map:
            # Substituted character: store all original characters this substituted character could represent
            possible_chars = common_substitutions_reverse_map[char]
        else:
            # Non-substituted character: store the current character as it already is in the password
            possible_chars = [char]

        # Temporary list storing updated possibilities including the current character or the original characters the current character may represent
        new_possibilities = []

        # Loop through each partial string/combination in current list of desubbed possibilities
        for possibility in desubbed_possibilities:
            # Loop through each character in possible desubbed characters
            for original_char in possible_chars:
                # Combine the possible combinations built so far with each possible character for the current position in the password
                new_possibilities.append(possibility + original_char)

        # Update the list of desubbed possibilities to include the new possible characters of the current iteration
        desubbed_possibilities = new_possibilities

    return desubbed_possibilities

# Each string in desubbed_possibilities acts as a base. For each base string,
# we create a new string for every possible original character for the current
# password character. That is how one base string produces multiple new strings,
# one per possible original character.

# If desubbed_possibilities currently contains four partial password strings
# and the current password character could represent three possible original
# characters (stored in possible_chars), then each possible character is appended
# to its own separate copy of each existing string (stored in new_possibilities).
# These newly created strings replace the old list, so desubbed_possibilities now
# contains 12 partial password possibilities.


# Define blocklist check function:
def blocklistCheck(password: str) -> bool:
    # Declare match variable to track whether a match has been found
    match = False

    # Hash password with SHA-1 and store it
    password_hash = hashlib.sha1(password.encode()).hexdigest()

    #  .encode() converts password to UTF-8 as SHA-1 expects bytes, not a string.
    # .hexdigest() converts the resulting binary hash to a readable hexadecimal
    # string so that it is compatible with the Pwned API's hex format.

    # Store first five characters of password hash for k-anonymity suppression
    password_hash_prefix = password_hash[:5]

    # HTTP request header for Have I Been Pwned API query (polite API usage and helps avoid rate-limiting or filtering issues)
    headers = {
        "User-Agent": "password-security-toolkit"
    }

    # We are providing the Have I Been Pwned API with identification by including
    # this header in our request.

    # Query Have I Been Pwned password API for password hash prefix
    # Pwned API returns suffix-only results (first five hash characters not included)
    pwned_results = requests.get(
        f'https://api.pwnedpasswords.com/range/{password_hash_prefix}', timeout=5, headers=headers)

    # Have I Been Pwned API documentation can be found at
    # https://haveibeenpwned.com/api/v3#PwnedPasswords

    # Ensure Pwned API query is successful by checking for HTTP 200 status code
    if pwned_results.status_code == 200:
        # Store Pwned suffix results with counts as list
        pwned_suffixes_and_counts = pwned_results.text.splitlines()

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
                # Match found:
                match = True
                return match

    # Check de-subbed versions of password if match is not found:
    if not match:
        # Create list containing all possible de-subbed versions of password
        desubbed_passwords = desubstitute(password)

        # Loop through each possible de-subbed version of password
        for desubbed_password in desubbed_passwords:
            # Hash current de-subbed version of password with SHA-1
            desubbed_hash = hashlib.sha1(
                desubbed_password.encode()).hexdigest()

            # Store first five characters of de-subbed password hash for k-anonymity suppression (Pwned API returns suffix-only, meaning the first five hash characters are not included)
            desubbed_hash_prefix = desubbed_hash[:5]

            # Query Have I Been Pwned password API for current de-subbed password hash prefix
            pwned_desubbed_suffix_results = requests.get(
                f'https://api.pwnedpasswords.com/range/{desubbed_hash_prefix}', timeout=5, headers=headers)

            # Ensure Pwned API query is successful by checking for HTTP 200 status code
            if pwned_results.status_code == 200:
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
                        # Match found:
                        match = True
                        return match
                    # Loop continues if match not found

    # Have I Been Pwned's API returns a multi-line string of suffixes whose
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
    