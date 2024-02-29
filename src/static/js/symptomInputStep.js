function showNextStep(nextStepId) {
    var currentStep = document.querySelector('.form-step:not([style*="display: none"])');
    var nextStep = document.getElementById(nextStepId);

    currentStep.style.display = 'none';
    nextStep.style.display = 'block';
}

function showPreviousStep(previousStepId) {
    var currentStep = document.querySelector('.form-step:not([style*="display: none"])');
    var previousStep = document.getElementById(previousStepId);

    currentStep.style.display = 'none';
    previousStep.style.display = 'block';
}

function showConfirmation() {
    var formData = new FormData(document.getElementById('predictionForm'));
    var confirmationText = '';
    for (var pair of formData.entries()) {
        confirmationText += pair[0]+ ': ' + pair[1] + '\n';
    }
    document.getElementById('confirmation-text').innerText = confirmationText;
    document.getElementById('confirmation-modal').style.display = 'block';
}

function submitForm() {
    // Submit the form data to the server
    // This would be an AJAX call in a real application
    console.log("Form submitted!");
    document.getElementById('confirmation-modal').style.display = 'none';
}

// Close modal when clicking the X button or outside the modal
var modal = document.getElementById('confirmation-modal');
var span = document.getElementsByClassName('close')[0];
span.onclick = function() {
    modal.style.display = 'none';
}
window.onclick = function(event) {
    if (event.target == modal) {
        modal.style.display = 'none';
    }
}
