// sample_project/config.js
// Node.js app configuration

const config = {
    database: {
        host: "localhost",
        port: 5432,
        name: "myapp_db",
        user: "root",
        password: "SuperSecret123!"   // Hardcoded secret (Sprint 2 target)
    },
    jwt_secret: "jwt-secret-key-do-not-share",
    api_key: "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
};

// XSS vulnerability (Sprint 2 target)
function renderUser(name) {
    document.getElementById("output").innerHTML = name;
}

// Unsafe eval (Sprint 2 target)
function runCode(userInput) {
    eval(userInput);
}

module.exports = config;
