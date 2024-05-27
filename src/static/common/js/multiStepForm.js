let emailExists = false; // Declare the flag outside the function

function showStep(stepNumber) {
    // Get all fieldsets
    let fieldsets = document.querySelectorAll('.registration-form fieldset');

    // Validate fields before proceeding to the next step
    if (stepNumber === 2) {
        // Validate personal information fields
        if (!document.getElementById('firstName').value || !document.getElementById('lastName').value || !document.getElementById('dob').value || !document.getElementById('gender').value) {
            alert('Please fill in all fields before proceeding.');
            return false;
        }
    } else if (stepNumber === 3) {
        // Validate contact information fields
        if (!document.getElementById('email').value || !document.getElementById('mobile').value) {
            alert('Please fill in all fields before proceeding.');
            return false;
        }
    } else if (stepNumber === 4) {
        // Validate password fields
        if (!document.getElementById('password').value || !document.getElementById('confirm_password').value) {
            alert('Please fill in all fields before proceeding.');
            return false;
        }

        // Validate password strength and match
        if (document.getElementById('password-strength').textContent !== 'Very Strong' || document.getElementById('password-match').textContent !== '') {
            alert('Please ensure your password is very strong and matches the confirm password field before proceeding.');
            return false;
        }
    }

    // Remove 'active' class from all fieldsets
    for (let i = 0; i < fieldsets.length; i++) {
        fieldsets[i].classList.remove('active');
    }

    // Add 'active' class to the current fieldset
    let currentFieldset = document.querySelector('#step' + stepNumber);
    currentFieldset.classList.add('active');

    // When navigating to the review step, copy the user's input to the review fields
    if (stepNumber === 4) {
        document.getElementById('review_firstName').textContent = document.getElementById('firstName').value;
        document.getElementById('review_lastName').textContent = document.getElementById('lastName').value;
        document.getElementById('review_dob').textContent = document.getElementById('dob').value;
        document.getElementById('review_gender').textContent = document.getElementById('gender').value;
        document.getElementById('review_email').textContent = document.getElementById('email').value;
        document.getElementById('review_mobile').textContent = document.getElementById('mobile').value;

        // Make an AJAX request to the server to register the user
        let xhr = new XMLHttpRequest();
        xhr.open('POST', '/register', true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onload = function() {
            if (xhr.status === 200) {
                var response = JSON.parse(xhr.responseText);
                if (response.error) {
                    // If the server returns an error message, display it in the review section
                    document.getElementById('review_email_error').textContent = response.error;
                    emailExists = true; // Set the flag to true
                } else {
                    emailExists = false; // Set the flag to false
                }
            }
        };
        var formData = new FormData(document.getElementById('registration-form'));
        xhr.send(new URLSearchParams(new FormData(formData)).toString());
    }

    // If the email already exists, prevent the form from being submitted
    if (emailExists) {
        return false;
    }
}


function editField(fieldName) {
    // Navigate back to the step containing the field to be edited
    if (fieldName === 'firstName' || fieldName === 'lastName' || fieldName === 'dob' || fieldName === 'gender') {
        showStep(1);
    } else if (fieldName === 'email' || fieldName === 'mobile') {
        showStep(2);
    }
}
