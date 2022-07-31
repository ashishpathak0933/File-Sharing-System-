const login = new XMLHttpRequest();
login.open("GET", "http://localhost:3000/request");
login.setRequestHeader("Content-type", "application/json");
login.send();
login.onload = function() {
    const obj = JSON.parse(this.responseText);
    for (let i=0; i<obj.length; i++) {
        const file = obj[i];
        console.log(file)
        /*const code = "<tr><td>" + file.fileName + "</td>" +
            "<td>" + getDate(file.date) + "</td>" +
            "<td>" + file.filesize + "</td>" +
            "<td><button onclick='download(\""+file.fileName+"\")'>Download</button></td>" +
            "<td><button onclick='deleteFile(\""+file.fileName+"\")'>Delete</button></td></tr>";
        document.getElementById('table').innerHTML += code;*/
    }
    console.log(obj)
}



function logout(){

}

function block(){

}