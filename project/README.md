# PASSWORD SECURITY TOOLKIT

#### Video Demo: <URL HERE>


#### Description:

This web-based application project is an educational toolkit containing two separate password tools created to demonstrate the knowledge I've gained throughout Harvard's online CS50x course. The first tool is a password strength checker that analyses a password submitted by the user and displays a score out of 100 along with basic feedback based on a set of criteria designed to evaluate its strength. Meanwhile, the second tool is an attack simulator that estimates the worst-case and average times various attack types require to crack the submitted password and displays the results.

The project utilises Python, HTML, CSS, JavaScript, and the Flask web application framework. The password strength test takes into account blocklist matches, minimum password length, password entropy, password composition, and instances of common patterns to determine the password's final score. The attack simulator estimates attack times for brute force attacks, dictionary attacks, brute force x dictionary hybrid attacks (a.k.a. suffix-prefix attacks), and rule-based mutation attacks.

This is my first self-developed project and is purely for educational purposes. It prioritises clarity and educational value over real-world accuracy by providing simplified versions of real security tools. As a result, there are multiple opportunities to improve this application in the future to make it both more accurate and more realistic. Note: Loading times may be slow for longer passwords.


#### How to run this project locally:

(1) Clone repository.
(2) Ensure Python and Flask are installed (optional: create and activate virtual environment to isolate dependencies).
(3) Install requirements from requirements.txt.
(4) Run application via Flask with `flask run` within project directory.


#### app.py:

This file is the controller file for the application that acts as the intermediary between the user's input (via HTML templates) and the application logic (via Python modules). It is responsible for getting the submitted password, computing its score and/or estimated attack times via module functions, and then updating the respective HTML templates with its response by rendering the respective template with the computed result values. 


#### analyser.py:

This is the module file used for the password strength checker side of the toolkit. It contains all the relevant functionality needed to compute a score based on the user's submitted password. Each included function corresponds to each of the five checks (blocklist, minimum length, entropy, composition, and pattern) needed to determine the total score, in addition to an extra function whose sole purpose is to generate the score feedback that is displayed underneath the final score. This process is performed in the controller file, and therefore requires this module to be imported into app.py.


#### simulator.py:

This is the module file used for the attack simulator side of the toolkit. It contains all the relevant functionality needed to calculate estimated attack times for the following attack types; brute force, dictionary, brute force x dictionary hybrid (a.k.a. suffix-prefix attack), and rule-based mutation. This module also contains an extra function that converts each of the raw computed time estimations (seconds) to more meaningful units for display purposes. This process is performed in the controller file, and therefore requires this module to be imported into app.py.


#### helpers.py:

The helpers module file solely contains the functionality needed to get all possible de-substituted variants of the submitted password. This refers to the process of identifying any Leetspeak characters (for instance, '@' representing 'a') used in the password, and returns a list containing all possible de-substituted variants generated from the password (limited to 200 variants), where any substituted Leetspeak characters are replaced with their potential original characters.


#### templates/:

A directory containing the templates for each HTML page of the application. It includes the HTML code for the homepage, password strength checker, and the attack simulator. It also includes the layout file that acts as the boilerplate for all the other templates. These templates can be re-rendered to include the application's result response to the user's requests.


#### static/:

A directory containing a variety of static (unchanging) files used to support the application. This includes two JavaScript files used to provide dynamic functionality for the strength checker and attack simulator HTML pages, a CSS file for HTML template styling, and a txt file containing the wordlist used in the attack simulator code.


#### Design Choices & Thoughts:

##### (1) Why use theoretical time estimations Vs real crack time?

- Real password cracking is impractical and generally unsuitable for demonstration purposes as strong passwords can take an extremely long time to crack. Therefore, this project calculates theoretical time estimations instead, based on: password length, character set size, and assumed attack speeds.

##### (2) Why are we storing the password list as a static file for the dictionary attack and hybrid attack simulations, instead of in an SQL database?

- SQL (Structured Query Language) is only needed if storing user data (such as, accounts, history, etc.). Furthermore, for the purposes of this application, the password list is only required to be readable (not writable) and does not need to be queryable, indexable, or possess user-specific persistence.  
- By storing the password list as a static .txt file in the project directory, we can read it into memory when we need it. 

##### (3) Why was Flask imported without SQLAlchemy?

- Flask provides sufficient functionality for routing and templating via Jinja2. Meanwhile, the SQLAlchemy extension was excluded from the Flask framework as the application did not make use of any relational data storage. 

##### (4) How did I decide on what version of the entropy formula to use?

- The entropy model for the password strength checker utilises the modern version of the entropy formula (length x log2(charset size)) as it's easier to understand and therefore implement for the educational scope of this project.
- It should be noted that entropy is only one metric among several metrics used to determine the password's strength as high entropy is no longer enough to guarantee a secure password.

##### (5) What does the password strength checker not take into consideration?

- Does not account for the password containing phrases or terms that are significant to the user. 
- Does not account for phrases or terms that connect to the user's username or the service the password is being used for. 
- Does not account for password reuse across multiple services which would indirectly increase the password's vulnerability. 
- Does not take into consideration frequency-based guessing prioritisation which may result in the password being cracked earlier if it follows a common pattern or structure that attackers may prioritise.

##### (6) How did I decide on the weightings of each check involved in the strength checker?

- A hierarchical weighting system was used, where different checks reward varying levels of scores depending on their relative impact on a password's strength. For instance, critical factors such as minimum length and blocklist matches have a greater impact on the password's final score than secondary factors such as character composition. This prevents weak passwords from scoring highly based on superficial criteria.
- Finally, weightings were refined iteratively with help from Claude. 

##### (7) Why are we hashing the submitted password with SHA-1 before querying Have I Been Pwned's API?

- The password is hashed locally with SHA‑1 and only the 5-character prefix of that hash is queried against Have I Been Pwned's API using k‑anonymity. The full hash and original plaintext password is never transmitted in accordance with the API's specification and general good security practice. 

##### (8) What are the limits of the password strength checker?

- Only supports Latin-based characters. Checks such as the entropy calculation utilise defined character set limits in the calculations, other languages may utilise a different character set and therefore would require their own additional code for entropy to be successfully calculated.
- Only considers ASCII symbols (a.k.a. special characters). Does not include symbols used in other standards, such as Unicode.
- Only supports common single character-substitutions when de-substituting a password. For example, '@' for 'a' is included, but '|)' for 'd' is not.

##### (9) Why does the pattern check utilise a three character minimum window size to classify a pattern?

- Three consecutive characters is a heuristic minimum used to detect a common sequence/pattern. It ensures the effectiveness of pattern detection while also preventing any negative impacts of performance or complexity.

##### (10) Why does the symbol detection used in multiple checks only look for ASCII special characters?

- ASCII symbols cover what the majority of people would actually use within their passwords and are universally accepted within passwords by all services.
- Unicode symbols are generally rare in passwords and including them would add further complexity unnecessary for the scope of this project.

##### (11) What is the purpose of the reverse mapping functionality used for the de-substitute function in the blocklist check?

- Reverse Mapping allows for fast lookup via values in dictionaries. By default, Python dictionary key lookup is O(1) while value lookup is O(n) as it must iterate through all key-value pairs and inspect their values to determine which keys map to the given value. Reverse mapping enables us to avoid value lookup entirely by treating the original values as keys in a separate dictionary. This achieves O(1) lookup time per character where lookup time was previously O(n) per character.
- For the purpose of the de-substitute function, we can query the reverse map with a value (substituted Leetspeak character) to find its original characters (original alphabetical or numeric characters). This introduces a space-time tradeoff, where we allocate additional memory to store the reversed mapping in exchange for faster lookup.
- Suggested by Claude to significantly improve lookup speeds with minimal additional code.

##### (12) Why did I decide to use Have I Been Pwned's API for the blocklist check instead of just a static .txt file of the most common passwords?

- The Pwned API holds millions of compromised passwords, while a static .txt file would typically hold the top 1,000-10,000 common passwords. Therefore, using the API is more thorough.
- The downsides to using the API over a static .txt file include: the device must be online for it to function, and significantly increased computational times and potential request hanging for extremely long passwords (this is prevented by limiting the amount of de-substituted variants being queried to a cap of 200).

##### (13) What is k-anonymity and why is it used before querying the Have I Been Pwned API in the blocklist check?

- k-anonymity is a data privacy technique that ensures each query is indistinguishable from at least k−1 others by only sending a partial hash to the API to prevent the full password hash from being exposed. Have I Been Pwned's password API utilises a k-anonymity model as its security measure. 

##### (14) Why does the input validation for the user's submitted password utilise JavaScript code instead of just using the maxlength HTML attribute?

- The maxlength HTML input attribute does not allow messages (alerts) to be sent directly to the user to explain why their input is invalid. On the other hand, JavaScript provides immediate feedback and can support custom value validation without the use of other languages.

##### (15) Why does the blocklist check override all subsequent checks and automatically return a final score of 0 if a match is found?

- If the submitted password is found in the results returned by the API query during the blocklist check, it is regarded as an instant failure, preventing subsequent checks and the password is assigned zero points. It is safe to assume that the password is highly vulnerable if this occurs and therefore indicates no reason to continue with the rest of the strength check. De-substituted variants are also checked to prevent trivial bypasses of the blocklist check that would imply false password strength. 

##### (16) Why does the password attack simulator operate on the password as plaintext rather than hashes (which would be more realistic)?

- Most applications store passwords as hashes instead of in the original plaintext form. So estimating the attack times based on an assumed hashrate is a more realistic representation of how an attacker would crack a password. However, it adds unnecessary complexity for the educational scope of this project. But it does present an opportunity for future development/improvement. 

##### (17) What reasoning was used for the assumptions made in the attack simulator?

- Since the attack simulator simply provides a time estimate for each attack type, including the Rule-based Mutation attack type, I assumed a conservative but realistic 20 rule mutations per word in the wordlist to account for common Leetspeak substitutions and single character appends. This is a simplifying assumption used to approximate the expansion of candidate space.
- Assumed constant benchmark speeds to represent the potential hardware capabilities an attacker may possess. This results in three varied benchmark speeds representing three different attack scenarios: an online attack (although this is usually limited even further by the service's rate limiting and is dependent on network latency), an offline attack, and an attack that utilises specialised hardware (cracking array, botnets, GPU clusters, etc.)

- **Strength Checker:**
	
	- The length of the password directly determines the maximum score the password can achieve.
	- A set of 32 ASCII symbols (not including space character) are used to determine which characters are counted as special characters in entropy check and composition check.
	- For the entropy calculation, the charset range is determined from the password's inclusion of the following 4 character type pools: 10 numerics, 26 lower, 26 upper, and 32 symbols.
	- Password de-substitution is limited to 200 variants to reduce loading times.
	- Blocklist check uses Have I Been Pwned's password API with k-anonymity to prevent password from being exposed during each query.
	- Pattern checks are limited to three specific pattern types: sequential chars, keyboard patterns, and consecutive repeated chars (3+).

- **Attack Simulator:**
	
	- Assumes benchmark speeds for three varying levels of computational hardware power that an attacker may possess: Online Attack Scenario - one thousand guesses per second (dependent on network latency and rate limiting of service), Offline Attack Scenario (with high-end GPU) - ten billion guesses per second, and Specialised Rig Scenario (cracking arrays, botnets, GPU clusters, etc.) - one hundred trillion guesses per second.
	- Utilises a standard top 10,000 most common passwords list to be used in dictionary attack estimate and hybrid attack estimate.
	- Hybrid attack simulation assumes the attacker would consider prefixes and suffixes to have a padding depth of up to 3 characters.
	- Rule-based Mutation attack simulation model assumes every word in the wordlist has an average of 20 rule-based mutations each to determine total candidate pool size.
	- Assumes a charset of 95 ASCII characters for brute force attack estimations.
	- Assumes a total of 42 possible ASCII symbols and digits (not including space character) are included in the charset used to determine what is and what isn't a special character in the hybrid attack model.

##### (18) How does this project's password strength checker compare with real-world password strength checkers?

- This project uses an analytical approach by utilising deterministic rules and simplified models to ensure educational clarity while still demonstrating technical knowledge obtained through the CS50x course. Real systems likely use more thorough probabilistic models with frequency analysis.

##### Other design choices:

- Features/aspects of the application that required additional research or were not previously familiar are accompanied by multi-line comments explaining their purpose and how they work.
- Assumptions, sources, and relevant implementation details are also stated via inline comments of code.
- Both maximum and average estimates are displayed in attack simulator to reflect best and worst case attack scenarios.

##### Opportunities for future features/improvements:

- Add mask attack type to attack simulator.
- Improve computation speed of strength check for extremely long passwords. 
- Add language detection and additional character sets for those languages that use different characters so that passwords using different character sets can be tested. 
- Include Unicode symbols in symbol detection for checks.