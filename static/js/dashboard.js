/**
 * PhishGuard Live - SOC Dashboard Charts
 * Renders high-resolution threat telemetry charts using Chart.js
 */

document.addEventListener("DOMContentLoaded", () => {
  // 1. Scan Activity Line Chart
  const activityCanvas = document.getElementById("scanActivityChart");
  if (activityCanvas && window.Chart) {
    const dates = JSON.parse(activityCanvas.getAttribute("data-dates") || "[]");
    const counts = JSON.parse(activityCanvas.getAttribute("data-counts") || "[]");

    const ctx = activityCanvas.getContext("2d");
    const gradient = ctx.createLinearGradient(0, 0, 0, 250);
    gradient.addColorStop(0, "rgba(56, 189, 248, 0.4)");
    gradient.addColorStop(1, "rgba(56, 189, 248, 0.0)");

    new Chart(activityCanvas, {
      type: "line",
      data: {
        labels: dates.length ? dates : ["Day 1", "Day 2", "Day 3", "Day 4", "Day 5", "Day 6", "Today"],
        datasets: [
          {
            label: "Scans Processed",
            data: counts.length ? counts : [0, 0, 0, 0, 0, 0, 0],
            borderColor: "#38bdf8",
            backgroundColor: gradient,
            fill: true,
            tension: 0.35,
            borderWidth: 2.5,
            pointBackgroundColor: "#00f2fe",
            pointBorderColor: "#fff",
            pointHoverRadius: 6
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(10, 16, 28, 0.95)",
            titleColor: "#38bdf8",
            bodyColor: "#f1f5f9",
            borderColor: "rgba(56, 189, 248, 0.3)",
            borderWidth: 1,
            padding: 10
          }
        },
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { color: "#64748b", font: { size: 11 } }
          },
          y: {
            beginAtZero: true,
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: {
              color: "#64748b",
              font: { size: 11 },
              precision: 0
            }
          }
        }
      }
    });
  }

  // 2. Verdict Distribution Doughnut Chart
  const verdictCanvas = document.getElementById("verdictDoughnutChart");
  if (verdictCanvas && window.Chart) {
    const safe = parseInt(verdictCanvas.getAttribute("data-safe") || "0");
    const suspicious = parseInt(verdictCanvas.getAttribute("data-suspicious") || "0");
    const phishing = parseInt(verdictCanvas.getAttribute("data-phishing") || "0");

    const total = safe + suspicious + phishing;
    const dataVals = total > 0 ? [safe, suspicious, phishing] : [1, 0, 0];
    const bgColors = total > 0 ? ["#10b981", "#f59e0b", "#ef4444"] : ["#334155", "#334155", "#334155"];

    new Chart(verdictCanvas, {
      type: "doughnut",
      data: {
        labels: ["Safe", "Suspicious", "Phishing"],
        datasets: [
          {
            data: dataVals,
            backgroundColor: bgColors,
            borderColor: "#0c1322",
            borderWidth: 3,
            hoverOffset: 4
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: "#94a3b8",
              font: { size: 11 },
              boxWidth: 12,
              padding: 15
            }
          },
          tooltip: {
            backgroundColor: "rgba(10, 16, 28, 0.95)",
            borderColor: "rgba(56, 189, 248, 0.3)",
            borderWidth: 1,
            callbacks: {
              label: (ctx) => {
                if (total === 0) return " No data yet";
                const val = ctx.raw;
                const pct = Math.round((val / total) * 100);
                return ` ${ctx.label}: ${val} (${pct}%)`;
              }
            }
          }
        },
        cutout: "70%"
      }
    });
  }
});
