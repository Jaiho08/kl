// Function to check session cookies
function checkSessionCookies() {
    let cookies = document.cookie;
    if (cookies) {
        alert("Session cookies detected!");
        console.log(1);
    } else {
        alert("No session cookies found.");
    }
}

// Function to get current directory info
function getCurrentDirectory() {
    let currentURL = window.location.href; // URL of the script
    let directory = currentURL.substring(0, currentURL.lastIndexOf('/'));
    return directory;
}

// Create a Blob with the directory info
function createBlobPreview() {
    let directoryInfo = "Current Directory: " + getCurrentDirectory();
    let blob = new Blob([directoryInfo], { type: "text/plain" });
    let blobURL = URL.createObjectURL(blob);

    // Create a preview link
    let link = document.createElement("a");
    link.href = blobURL;
    link.download = "directory_info.txt";
    link.innerText = "Download Directory Info";
    document.body.appendChild(link);
}

// Run functions when the script loads
checkSessionCookies();
createBlobPreview();
