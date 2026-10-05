const form = document.getElementById("scanForm");
const button = document.getElementById("scanButton");
const buttonText = document.getElementById("buttonText");
const spinner = document.getElementById("loadingSpinner");

form.addEventListener("submit", () => {

    button.disabled = true;

    button.classList.add("opacity-80");

    buttonText.textContent = "Analyzing URL...";

    spinner.classList.remove("hidden");

});