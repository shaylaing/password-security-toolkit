// Visibility functionality for more information regarding attack types:
// Listen for user clicking 'show more' button
document.getElementById("showMore").addEventListener("click", function () {
    // Get paragraph element containing extra information
    const extraInfo = document.getElementById("moreInfo");

    // Toggle visibility of extra information
    extraInfo.hidden = !extraInfo.hidden;
});
