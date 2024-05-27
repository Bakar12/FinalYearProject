function validateReview() {
    // Get all the review fields
    var reviewFields = ['review_firstName', 'review_lastName', 'review_dob', 'review_gender', 'review_email', 'review_mobile'];
    var isValid = true;

    // Iterate over each field
    for (var i = 0; i < reviewFields.length; i++) {
        // Get the field value
        var fieldValue = document.getElementById(reviewFields[i]).textContent;

        // Check if the field is empty
        if (fieldValue === '') {
            // If the field is empty, display an error message and set isValid to false
            document.getElementById('error_' + reviewFields[i].split('_')[1]).textContent = 'Please fill in this field.';
            isValid = false;
        } else {
            // If the field is not empty, clear the error message
            document.getElementById('error_' + reviewFields[i].split('_')[1]).textContent = '';
        }
    }

    // If all fields are filled in, return true to allow form submission
    return isValid;
}