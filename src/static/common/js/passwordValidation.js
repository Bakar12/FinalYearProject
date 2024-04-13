function checkPasswordStrength() {
    let strengthText = document.getElementById('password-strength');
    let password = document.getElementById('password').value;
    let strength = 0;

    if (password.length >= 8) {
        strength += 1;
    }
    if (password.match(/[a-z]+/)) {
        strength += 1;
    }
    if (password.match(/[A-Z]+/)) {
        strength += 1;
    }
    if (password.match(/[0-9]+/)) {
        strength += 1;
    }
    if (password.match(/[\W]+/)) {
        strength += 1;
    }

    switch (strength) {
        case 0:
            strengthText.innerHTML = '';
            break;
        case 1:
            strengthText.innerHTML = 'Very Weak';
            break;
        case 2:
            strengthText.innerHTML = 'Weak';
            break;
        case 3:
            strengthText.innerHTML = 'Medium';
            break;
        case 4:
            strengthText.innerHTML = 'Strong';
            break;
        case 5:
            strengthText.innerHTML = 'Very Strong';
            break;
    }
}

function validatePassword() {
    let password = document.getElementById('password').value;
    let confirm_password = document.getElementById('confirm_password').value;
    let passwordMatchText = document.getElementById('password-match');

    if (password !== confirm_password) {
        passwordMatchText.innerHTML = 'Passwords do not match';
        return false;
    } else {
        passwordMatchText.innerHTML = '';
        return true;
    }
}
