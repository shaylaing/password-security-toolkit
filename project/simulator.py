from helpers import desubstitute

# Read in SecLists' Top 10,000 Common Passwords .txt file as list (for dictionary attack)
with open('static/10k-most-common.txt', 'r') as file:
    wordlist = file.read().splitlines()

# Convert wordlist to set for faster lookup (O(1)) (for all other attack types)
wordset = set(wordlist)

# NOTE: Source for wordlist can be found at:
# https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt


# Declare assumptions for three levels of computational hardware power the attacker could possess:
# Online Attack Scenario - one thousand guesses per second (assumes minimal rate limiting and poor configuration)
ONLINE_BENCHMARK = 10 ** 3

# Offline Attack Scenario - ten billion guesses per second (assumes high-end GPU)
OFFLINE_BENCHMARK = 10 ** 10

# Specialised Attack Scenario - one hundred trillion guesses per second (cracking arrays, botnets, GPU clusters, etc.)
SPECIALISED_BENCHMARK = 10 ** 14

# NOTE: Sources used to inform hardware assumptions can be found at:
# https://www.onlinehashcrack.com/guides/password-recovery/bruteforce-attack-limits-calculate-time-needed.php
# https://www.grc.com/haystack.htm


# Define every possible ASCII symbol/special character for entropy check and composition check
SYMBOLS_SET = {'!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
               ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~'}


# Define time conversion function (automatic unit scaling for raw times in seconds):
def convert_times_to_units(times: dict) -> dict:
    # Initialise dict to store converted times and units
    converted_times = {}

    # Convert each raw time estimate to largest meaningful unit:
    # Loop through each key and time value in raw times dict
    for name, time in times.items():
        # Seconds check:
        if time < 60:
            # Convert time to have 3 decimal places
            time = round(time, 3)

            # Add converted time and unit to dict
            unit = "seconds"
            converted_times[name] = (time, unit)
        # Minutes check:
        elif time < 3600:
            # Convert time to minutes
            converted_time = time / 60

            # Convert time to have 3 decimal places
            converted_time = round(converted_time, 3)
                         
            # Add converted time and unit to dict
            unit = "minutes"
            converted_times[name] = (converted_time, unit)
        # Hours check:
        elif time < 86400:
            # Convert time to hours
            converted_time = time / 3600

            # Convert time to have 3 decimal places
            converted_time = round(converted_time, 3)

            # Add converted time and unit to dict
            unit = "hours"
            converted_times[name] = (converted_time, unit)
        # Days check:
        elif time < 31536000:
            # Convert time to days
            converted_time = time / 86400
            
            # Round time to nearest whole number
            converted_time = int(round(converted_time))

            # Add converted time and unit to dict
            unit = "days"
            converted_times[name] = (converted_time, unit)
        # Years check:
        elif time < 31536000000:
            # Convert time to years:
            converted_time = time / 31536000

            # Round time to nearest whole number
            converted_time = int(round(converted_time))

            # Add converted time and unit to dict
            unit = "years"
            converted_times[name] = (converted_time, unit)
        # 'Uncrackable' check:
        else:
            # Convert time to years (purely for presentation)
            converted_time = time / 31536000

            # Round time to nearest whole number
            converted_time = int(round(converted_time))

            # Add converted time and unit to dict
            unit = "years (practically uncrackable)"
            converted_times[name] = (converted_time, unit)
    
    return converted_times


# Define brute force attack simulation function:
def brute_force_sim(password: str) -> dict:
    # Calculate and store length of password
    length = len(password)

    # Initialise maximum charset range (assumes that attacker is taking into account ASCII characters only (95 chars), not other standards like Unicode)
    MAX_CHARSET_RANGE = 95

    # Calculate and store keyspace (total possible combinations)
    keyspace = MAX_CHARSET_RANGE ** length

    # Create dict to store attack time estimates
    times = {}

    # Calculate attack time estimates for worst case (maximum time) and store them in times dict
    times["online_maximum_time"] = keyspace / ONLINE_BENCHMARK
    times["offline_maximum_time"] = keyspace / OFFLINE_BENCHMARK
    times["specialised_maximum_time"] = keyspace / SPECIALISED_BENCHMARK

    # Calculate average attack time estimates and store them in times dict
    times["online_average_time"] = (keyspace / 2) / ONLINE_BENCHMARK
    times["offline_average_time"] = (keyspace / 2) / OFFLINE_BENCHMARK
    times["specialised_average_time"] = (keyspace / 2) / SPECIALISED_BENCHMARK

    # Convert each time estimate in times dict to largest meaningful unit and return it
    return convert_times_to_units(times)


# Define dictionary attack simulation function:
def dictionary_sim(password: str) -> None | dict:
    # Initialise flag variable for vulnerability
    vulnerable = False

    # Search for password in wordlist to determine vulnerability and store position if found:
    # Loop through each word in wordlist
    for i, word in enumerate(wordlist):
        if word == password:
            # Match found, store position and update flag variable
            match_position = i
            vulnerable = True
            break
    
    # If match found:
    if vulnerable:
        # Create dict to store attack time estimates
        times = {}

        # Determine total guesses attacker would need to make to crack password (and prevent position 0)
        guesses = match_position + 1

        # Calculate attack time estimates for worst case (maximum time) and store them in times dict
        times["online_maximum_time"] = guesses / ONLINE_BENCHMARK
        times["offline_maximum_time"] = guesses / OFFLINE_BENCHMARK
        times["specialised_maximum_time"] = guesses / SPECIALISED_BENCHMARK

        # Calculate average attack time estimates and store them in times dict
        times["online_average_time"] = (guesses / 2) / ONLINE_BENCHMARK
        times["offline_average_time"] = (guesses / 2) / OFFLINE_BENCHMARK
        times["specialised_average_time"] = (guesses / 2) / SPECIALISED_BENCHMARK

        # Convert each time estimate in times dict to largest meaningful unit and return it
        return convert_times_to_units(times)

    # If match not found:
    else:
        return None


# Define brute force x dictionary hybrid attack simulation function (a.k.a. suffix-prefix attack):
def hybrid_sim(password: str) -> None | dict:

    # Hardcode estimated attack times for hybrid attack (times aren't dependent on password):
    # Calculate total possible character mutations for both prefixes OR suffixes
    maximum_mutations = 2 * (42 + (42 ** 2) + (42 ** 3)) 

    # NOTE: Derives total possible number of prepended and appended symbol mutations from ASCII standard
    # NOTE: Estimates prefix and suffix mutations independently of each other 
    # NOTE: Charset size of 42 characters (32 symbols + 10 digits)

    # Calculate maximum possible combinations attacker needs to check to crack password (worst case)
    total_combinations = len(wordset) * maximum_mutations

    # Initialise dict with times hardcoded
    times = {
        # Attack time estimates for worst case (maximum time)
        "online_maximum_time": total_combinations / ONLINE_BENCHMARK,
        "offline_maximum_time": total_combinations / OFFLINE_BENCHMARK,
        "specialised_maximum_time": total_combinations / SPECIALISED_BENCHMARK,

        # Average attack time estimates
        "online_average_time": (total_combinations / 2) / ONLINE_BENCHMARK,
        "offline_average_time": (total_combinations / 2) / OFFLINE_BENCHMARK,
        "specialised_average_time": (total_combinations / 2) / SPECIALISED_BENCHMARK,
    }

    # Search for password in wordlist to determine vulnerability:
    # Check if password as-it appears in wordlist
    if password in wordset:
        # Match found, return early
        return convert_times_to_units(times)
    
    # Match not found, check if hybrid versions of password (without 1-3 character prefixes and suffixes) appears in wordlist:
    else:
        # Initialise prefix count variable and suffix count variable
        prefix_count = 0
        suffix_count = 0

        # Count how many numbers or symbols appear in prefix (first 3 chars) of password contiguously and store total
        for char in password[:3]:       # Iterates from start to 3rd char
            if char.isdigit() or char in SYMBOLS_SET:
                prefix_count += 1
            
            # If current character is not a symbol or number, end loop 
            else:
                break
       
        # Count how many numbers or symbols appear in suffix (last 3 chars) of password contiguously and store total
        for char in password[-3:][::-1]:       # Iterates from 3rd last char till end
            if char.isdigit() or char in SYMBOLS_SET:
                suffix_count += 1
            
            # If current character is not a symbol or number, end loop 
            else:
                break
        
        # Gradually remove each prefix and suffix char one by one and check if remaining password appears in wordlist:
        # Iterate for the total prefix count 
        for p in range(prefix_count + 1):
            # Iterate for the total suffix count
            for s in range(suffix_count + 1):
                # Prevent original password from being checked again
                if p == 0 and s == 0:
                    continue
                
                # Prevent :-0 edge case in slicing
                if s == 0:
                    # Check if remaining password (without prefix chars) 
                    if password[p:] in wordset:
                        # Match found, update flag variable and return early
                        return convert_times_to_units(times)
                
                # Continue check if there's still prefixes and suffixes to be removed
                else:
                    if password[p:-s] in wordset:
                        # Match found, return early
                        return convert_times_to_units(times)
                
        # If match not found:
        return None
    
    # NOTE: Assumes a padding depth limit of up to three characters for the prefix and suffix. 
    # NOTE: Estimated attack times remain constant as the attacker would need to try all possible 
    # combinations if they don't know the composition of password beforehand.
    # NOTE: Utlises a standard wordlist size of the top 10,000 most common passwords, in addition to
    # assuming ASCII characters only.


# Define rule-based mutation attack simulation function:
def rule_based_mutation_sim(password: str) -> None | dict:
    # Initialise flag variable for vulnerability
    vulnerable = False

    # Get all de-substituted variants of password
    desubbed_passwords = desubstitute(password)

    # Return None early if no substitutions were found for password (not vulnerable)
    if len(desubbed_passwords) == 1 and desubbed_passwords[0] == password.lower():
        return None

    # Search for passwords in wordlist to determine vulnerability:
    # Check if any de-subtituted variants of the password appear in wordlist
    for variant in desubbed_passwords:
        if variant in wordset:
            # Match found, update flag variable
            vulnerable = True
            break
    
    # If match found:
    if vulnerable:
        # Create dict to store attack time estimates
        times = {}

        # Calculate attack time estimates for worst case (maximum time) and store them in times dict
        times["online_maximum_time"] = (len(wordset) * 20) / ONLINE_BENCHMARK
        times["offline_maximum_time"] = (len(wordset) * 20) / OFFLINE_BENCHMARK
        times["specialised_maximum_time"] = (len(wordset) * 20) / SPECIALISED_BENCHMARK

        # Calculate average attack time estimates and store them in times dict
        times["online_average_time"] = ((len(wordset) * 20) / 2) / ONLINE_BENCHMARK
        times["offline_average_time"] = ((len(wordset) * 20) / 2) / OFFLINE_BENCHMARK
        times["specialised_average_time"] = ((len(wordset) * 20) / 2) / SPECIALISED_BENCHMARK

        # NOTE: For the attack time calculation/estimates, the model assumes an average of ~20 
        # rule-based mutations per word in the wordlist to account for common Leetspeak 
        # substitutions, capitalisaion, and symbol replacements. This value assumption is used 
        # because the attacker cannot know the correct mutations in advance and must attempt 
        # multiple password variants.

        # Convert each time estimate in times dict to largest meaningful unit and return it
        return convert_times_to_units(times)
    
    # If match not found:
    else:
        return None
