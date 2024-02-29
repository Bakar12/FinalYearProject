function showStep(stepNumber) {
    // Get all fieldsets
    let fieldsets = document.querySelectorAll('.registration-form fieldset');

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