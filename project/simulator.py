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
