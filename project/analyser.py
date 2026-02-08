from math import log2

# Define every possible ASCII symbol/special character for future checks
SYMBOLS_SET = {'!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
           ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~'}

# Define blocklist check:
def blocklistCheck(password):
    # Define dict of commonly substituted characters and their singular substitutions (a.k.a. Leet Speak)
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

# Reverse mapping for desubstitute function