const API_URL = "http://127.0.0.1:5000"; // Change if necessary

async function generateComments() {
    const code = document.getElementById("codeInput").value;
    const language = document.getElementById("language").value;

    const response = await fetch(`${API_URL}/generate-comments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, language })
    });

    const result = await response.json();
    document.getElementById("output").innerText = result.commentedCode || result.error;
}

async function runCode() {
    const code = document.getElementById("codeInput").value;
    const language = document.getElementById("language").value;

    const response = await fetch(`${API_URL}/execute-code`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, language })
    });

    const result = await response.json();
    document.getElementById("output").innerText = result.output || result.error;
}
