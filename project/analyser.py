from math import log2

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

'''Dictionary lookup is slow as it searches via keys by default. Reverse 
mapping enables us to flip the dictionary around so that we treat its values
as keys instead so that we can search via its values and speed up the process
of searching the dictionary. Provides improvement from O(n) per character to 
O(1) per character.'''


# Define function to generate all possible original passwords by reversing character substitutions
def desubstitute(password: str) -> list[str]:
    # Initialise list with empty string to act as starting base for building combinations
    desubbed_possibilities = [""]

    # Loop through each character in the password 
    for char in password:
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
        
        # Update the list of desubbed possibilities to include the updated possibilities that include the possible characters of the current iteration
        desubbed_possibilities = new_possibilities

    return desubbed_possibilities

'''Each string in desubbed_possibilities acts as a base. For each base string, 
we create a new string for every possible original character for the current 
password character. That is how one base string produces multiple new strings, 
one per possible original character.'''

'''If desubbed_possibilities currently contains four partial password strings 
and the current password character could represent three possible original 
characters (stored in possible_chars), then each possible character is appended 
to its own separate copy of each existing string (stored in new_possibilities). 
These newly created strings replace the old list, so desubbed_possibilities now 
contains 12 partial password possibilities.'''


# Define blocklist check function:
def blocklistCheck(password: str) -> int:
    return 