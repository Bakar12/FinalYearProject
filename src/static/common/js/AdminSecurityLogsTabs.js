function openLogs(evt, logType) {
    var i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tablinks");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
    }
    document.getElementById(logType).style.display = "block";
    evt.currentTarget.className += " active";

    if (logType === 'UserLogs') {
        fetch('/admin/security_logs/users')
            .then(response => response.json())
            .then(data => {
                var table = createTable(data);
                document.getElementById('userLogs').innerHTML = table;
            });
    } else if (logType === 'AdminLogs') {
        fetch('/admin/security_logs/admins')
            .then(response => response.json())
            .then(data => {
                var table = createTable(data);
                document.getElementById('adminLogs').innerHTML = table;
            });
    }
}

function createTable(data) {
    var table = '<table><tr><th>ID</th><th>Name</th><th>Action</th><th>Date</th></tr>';
    for (var i = 0; i < data.length; i++) {
        table += '<tr><td>' + data[i].id + '</td><td>' + data[i].name + '</td><td>' + data[i].action + '</td><td>' + data[i].date + '</td></tr>';
    }
    table += '</table>';
    return table;
}

// Get the element with id="defaultOpen" and click on it
document.getElementById("defaultOpen").click();