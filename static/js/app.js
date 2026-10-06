/**
 * PhishGuard Live - Global Application Script
 * Live SOC UTC clock, mobile navigation, toast notifications
 */

document.addEventListener("DOMContentLoaded", () => {
  // Mobile sidebar toggle
  const mobileToggle = document.getElementById("mobileToggle");
  const sidebar = document.querySelector(".soc-sidebar");

  if (mobileToggle && sidebar) {
    mobileToggle.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });

    // Close when clicking outside on mobile
    document.addEventListener("click", (e) => {
      if (
        sidebar.classList.contains("open") &&
        !sidebar.contains(e.target) &&
        !mobileToggle.contains(e.target)
      ) {
        sidebar.classList.remove("open");
      }
    });
  }

  // Live UTC Clock for SOC authenticity
  const clockElement = document.getElementById("socLiveClock");
  if (clockElement) {
    const updateClock = () => {
      const now = new Date();
      clockElement.textContent = now.toUTCString().replace("GMT", "UTC");
    };
    updateClock();
    setInterval(updateClock, 1000);
  }

  // Auto-dismiss alerts after 6 seconds
  const flashAlerts = document.querySelectorAll(".alert-cyber");
  flashAlerts.forEach((alert) => {
    setTimeout(() => {
      alert.style.transition = "opacity 0.5s ease";
      alert.style.opacity = "0";
      setTimeout(() => alert.remove(), 500);
    }, 6000);
  });
});
