// Input validation for password submission:
// Listen for user submitting their entered password
document
    .getElementById("strengthAnalyser")
    .addEventListener("submit", function (event) {
        // Get password input text box
        const passwordField = document.getElementById("passwordTextbox");

        // Prevent inputted password from being longer than 64 characters
        if (passwordField.value.length > 64) {
            // Stop submission
            event.preventDefault();

            // Hide results
            document.getElementById("results").hidden = true;

            // Show error message
            document.getElementById("client-length-error").hidden = false;
        }
    });
