from helpers import desubstitute

# Read in SecLists' Top 10,000 Common Passwords .txt file as list (for dictionary attack)
with open('10k-most-common.txt', 'r') as file:
    wordlist = file.read().splitlines()

# Convert wordlist to set for faster lookup (O(1)) (for all other attack types)
wordset = set(wordlist)

# Source for wordlist can be found at:
# https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt


# Declare assumptions for three levels of computational hardware power the attacker could possess:
# Online Attack Scenario - one thousand guesses per second (assumes minimal rate limiting and poor configuration)
online_benchmark = 10 ** 3

# Offline Attack Scenario - ten billion guesses per second (assumes high-end GPU)
offline_benchmark = 10 ** 10

# Specialised Attack Scenario - one hundred trillion guesses per second (cracking arrays, botnets, GPU clusters, etc.)
specialised_benchmark = 10 ** 14

# Sources used to inform hardware assumptions can be found at:
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
