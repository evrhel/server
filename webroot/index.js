
function getCookie(name) {
    let cookies = document.cookie.split(";");
    for (let cookie of cookies) {
        let parts = cookie.split("=");
        if (parts[0].trim() === name) {
            return parts[1];
        }
    }
    return "";
}

// submit login form
function login() {
    let username = document.getElementById("username").value;
    let password = document.getElementById("password").value;

    if (username === "" || password === "") {
        alert("Please enter username and password");
        return;
    }

    let body = {
        "username": username,
        "password": password  
    };

    fetch("/app/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
    }).then(response => {
        if (response.status === 200) {
            document.location.reload();
        } else {
            alert("Login failed");
        }
    }).catch(error => {
        console.log(error);
    });
}

function submitLoginForm(event) {
    event.preventDefault();
    login();
}

// submit logout form
function logout() {
    fetch("/app/logout", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({})
    }).then(response => {
        if (response.status === 200) {
            document.location.reload();
        } else {
            alert("Logout failed");
        }
    }).catch(error => {
        console.log(error);
    });
}

// fetch user data from server
function getUserData() {
    return fetch("/app/user", {
        method: "POST"
    });
}

// setup page
function setup() {
    let loginContainer = document.getElementById("login-container");
    let userInfoContainer = document.getElementById("user-info-container");
    let logoutContainer = document.getElementById("logout-container");

    loginContainer.hidden = true;
    userInfoContainer.hidden = true;
    logoutContainer.hidden = true;

    // make request to server to get data
    getUserData().then(response => {
        if (response.status === 200) {
            response.json().then(data => {
                if (!data.username) {
                    // not logged in
                    loginContainer.hidden = false;
                    userInfoContainer.hidden = true;
                    logoutContainer.hidden = true;
                    return;
                }

                loginContainer.hidden = true;
                userInfoContainer.hidden = false;
                logoutContainer.hidden = false;

                document.getElementById("info-username").innerHTML = data.username;
            });
        } else {
            loginContainer.hidden = false;
            userInfoContainer.hidden = true;
            logoutContainer.hidden = true;
        }
    }).catch(error => {
        console.log(error);
    });
}

setup();
