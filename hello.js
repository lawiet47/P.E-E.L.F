var payload = {
    "name": "ebeninamu.com",
    "url": "ebeninamu.com",
    "audience_total": 56565
};
var token = '';
function getcsrf(){
    var url = 'https://dev.primetag.com/'
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            var div = document.createElement('div');
            div.innerHTML = xhr.responseText;
            document.body.appendChild(div);
            token = document.querySelectorAll('[type="hidden"]')[4].value;
        };
    };
    xhr.open('GET', url, true);
    xhr.send(null);
}
function postdata() {
    var url = 'https://dev.primetag.com/api/profiles/1150/platforms/4';
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            console.log(xhr.responseText);
        };
    };
    xhr.open('POST', url, true);
    console.log(token);
    xhr.setRequestHeader('X-CSRFToken', token);
    xhr.withCredentials = "true";
    xhr.send(JSON.stringify(payload));
};
getcsrf();
postdata();
