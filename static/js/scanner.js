/**
 * PhishGuard Live - URL Threat Scanner Interaction Script
 * Animated scanner radar, quick demonstration sample URL chips
 */

document.addEventListener("DOMContentLoaded", () => {
  const scanForm = document.getElementById("scanForm");
  const scanInput = document.getElementById("urlInput");
  const scanBtn = document.getElementById("scanBtn");
  const scanLoadingOverlay = document.getElementById("scanLoadingOverlay");
  const scanStatusMsg = document.getElementById("scanStatusMsg");

  // Sample quick test pills
  const demoChips = document.querySelectorAll(".demo-pill");
  demoChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const url = chip.getAttribute("data-url");
      if (scanInput && url) {
        scanInput.value = url;
        scanInput.focus();
      }
    });
  });

  // Form submission animation
  if (scanForm && scanBtn) {
    scanForm.addEventListener("submit", (e) => {
      const val = scanInput ? scanInput.value.trim() : "";
      if (!val) {
        e.preventDefault();
        alert("Please enter a valid URL to analyze.");
        return;
      }

      // Display animated scanning overlay
      if (scanLoadingOverlay) {
        scanLoadingOverlay.style.display = "flex";
      }

      // Disable button
      scanBtn.disabled = true;
      scanBtn.innerHTML = `<i class="fas fa-circle-notch fa-spin"></i> Analyzing...`;

      // Cycle SOC status text
      const messages = [
        "Parsing URL syntax & structural schema...",
        "Evaluating Shannon domain entropy...",
        "Checking brand spoofing heuristics...",
        "Inspecting TLD & lexical obfuscation...",
        "Synthesizing threat score matrix..."
      ];
      let msgIdx = 0;
      setInterval(() => {
        msgIdx = (msgIdx + 1) % messages.length;
        if (scanStatusMsg) {
          scanStatusMsg.textContent = messages[msgIdx];
        }
      }, 400);
    });
  }
});
