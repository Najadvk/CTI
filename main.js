document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeDiv = document.getElementById("detected-type");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const ioc = input.value.trim();
    const type = detectIOC(ioc);
    detectedTypeDiv.textContent = type || "unknown";
    if (!type) return;

   
