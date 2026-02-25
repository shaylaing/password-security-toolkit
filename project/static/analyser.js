// Listen for user submitting their inputted password
document.getElementById("strengthAnalyser").addEventListener("submit", function(event){
    // Get password input textbox 
    const passwordField = document.getElementById("passwordTextbox");

    // Prevent inputted password from being longer than 64 characters
    if (passwordField.value.length > 64) {
        // Stop submission
        event.preventDefault()

        // If password length is over 64 characters, show error message
        alert("400: Inputted password is too long.")
    }
});
