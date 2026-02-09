from math import log2
from itertools import product

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
common_substitutions_reverse_map = {}      # Initialise empty dict for reverse map
for key, vals in COMMON_SUBSTITUTIONS.items():      # Take each key (real char) and its list of substitutions (values) (.items prevents default key-only iteration over dict)
    for val in vals:        # Take each value in values (subbed chars) 
         common_substitutions_reverse_map.setdefault(val, []).append(key)      # Register value (subbed char) as key to reverse map with an empty list as its value, and append each matching real char to that key (subbed char)


# Define function for password desubstitution
def desubstitute(password: str):
    # Initialise empty list to store all partial strings built so far
    desubbed_possibilities = [""]

    # Loop through each character in password
    for char in password:
        # Check for that character in reverse map
        if char in common_substitutions_reverse_map:
            # Add regular characters matching that substituted character to list of possible characters
            possible_chars = common_substitutions_reverse_map[char]
        else:
            # Add character as is to list of possible characters if not recognised as a substituted character 
            possible_chars = char
        
        # Initialise temporary list to store possible desubbed password combinations
        combinations = []

        # Loop through each partial string in current desubbed possibilities
        for possibility in desubbed_possibilities:
            # Loop through each character in possible desubbed characters
            for char in possible_chars:
                # Append each possible character to each desubbed password possibility
                combinations.append(possibility + char) 
        
        # Store completed desubbed password possibilities in permanent list
        desubbed_possibilities = combinations

    return desubbed_possibilities





          



          
                    
          
               


# Define blocklist check:
def blocklistCheck(password: str) -> int:
