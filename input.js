// ❌ Vulnerable Pattern – directly inserting user input into the DOM
const name = window.location.search.replace("?name=", "");
document.getElementById("output").innerHTML = name; 
