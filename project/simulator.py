from helpers import desubstitute

# Read in SecLists' Top 10,000 Common Passwords .txt file as list (for dictionary attack)
with open('10k-most-common.txt', 'r') as file:
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
# https://www.grc.com/haystack.htmhttps://www.grc.com/haystack.htm 


# Define time conversion function (automatic unit scaling for raw times in seconds):
def convert_times_to_units(times: dict) -> dict:
    # Initialise dict to store converted times and units
    converted_times = {}

    # Convert each raw time estimate to largest meaningful unit:
    # Loop through each key and time value in raw times dict
    for name, time in times.items():
        # Seconds check:
        if time < 60:
            # Add converted time and unit to dict
            unit = "seconds"
            converted_times[name] = (time, unit)
        # Minutes check:
        elif time < 3600:
            # Convert time to minutes
            converted_time = time / 60
            # Add converted time and unit to dict
            unit = "minutes"
            converted_times[name] = (converted_time, unit)
        # Hours check:
        elif time < 86400:
            # Convert time to hours
            converted_time = time / 3600
            # Add converted time and unit to dict
            unit = "hours"
            converted_times[name] = (converted_time, unit)
        # Days check:
        elif time < 31536000:
            # Convert time to days
            converted_time = time / 86400
            # Add converted time and unit to dict
            unit = "days"
            converted_times[name] = (converted_time, unit)
        # Years check:
        elif time < 31536000000:
            # Convert time to years:
            converted_time = time / 31536000
            # Add converted time and unit to dict
            unit = "years"
            converted_times[name] = (converted_time, unit)
        # 'Uncrackable' check:
        else:
            # Convert time to years (purely for presentation)
            converted_time = time / 31536000
            # Add converted time and unit to dict
            unit = "effectively uncrackable"
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


# Define brute force x dictionary hybrid attack simulation function (a.k.a. suffix-prefix attack)
def hybrid_sim(password: str) -> None | dict:
    # Initialise flag variable for vulnerability
    vulnerable = False

    # Hardcode estimated attack times for hybrid attack (times aren't dependent on password):
    # Calculate total possible character mutations for both prefixes and suffixes
    maximum_mutations = 2 * (43 + (43 ** 2) + (43 ** 3)) 

    # NOTE: Derives total possible number of prepended and appended symbol mutations from ASCII standard
    # NOTE: Estimates prefix and suffix mutations independently of each other 

    # Calculate maximium possible combinations attacker needs to check to crack password (worst case)
    total_combinations = len(wordset) * maximum_mutations

    # Initialise dict with times hardcoded
    times = {
        # Attack time estimates for worst case (maximum time)
        times
        # Average attack time estimates
        
    }



    # Search for password in wordlist to determine vulnerability:
    # Check if password as-it appears in wordlist
    if password in wordset:
        # Match found, update flag variable
        vulnerable = True
