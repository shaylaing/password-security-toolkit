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


# Reverse mapping for desubstitute function (suggested by Claude to allow for fast value lookup on the COMMON_SUBSTITUTIONS dict)
common_substitutions_reverse_map = {}      # Initialise empty dict for reverse map
for key, vals in COMMON_SUBSTITUTIONS.items():      # Take each key (real char) and its list of substitutions (values) (.items prevents default key-only iteration over dict)
    for val in vals:        # Take each value in values (subbed chars) 
         common_substitutions_reverse_map.setdefault(val, []).append(key)      # Register value (subbed char) as key to reverse map with an empty list as its value, and append each matching real char to that key (subbed char)


# Define blocklist check:
def blocklistCheck(password):
