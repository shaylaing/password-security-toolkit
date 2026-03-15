// Visibility functionality for more information regarding attack types:
// Listen for user clicking 'show more' button
document.getElementById("showMore").addEventListener("click", function(event){
    // Get paragraph element containing extra information
    const extraInfo = document.getElementById("moreInfo")

    // Flip visibility of extra information to opposite of current visibility
    extraInfo.hidden = !extraInfo.hidden
});
