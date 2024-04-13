function editField(fieldId) {
    var span = document.getElementById(fieldId);
    var currentValue = span.innerText;
    span.innerHTML = '<input type="text" value="' + currentValue + '" onBlur="saveField(\'' + fieldId + '\', this.value)" />';
    span.childNodes[0].focus();
}

function saveField(fieldId, newValue) {
    // Implement the save functionality here, possibly sending the new value to the server via Ajax
    var span = document.getElementById(fieldId);
    span.innerText = newValue; // Update the display with the new value
    // TODO: Add Ajax call to save the new value
}

var loadFile = function (event) {
    var image = document.getElementById("output");
    image.src = URL.createObjectURL(event.target.files[0]);
};
