// Chart creation and management
const Charts = {
  trafficChart: null,

  createTrafficChart(data) {
    const ctx = document.getElementById("trafficChart").getContext("2d");

    if (this.trafficChart) this.trafficChart.destroy();

    if (!data || data.length === 0) {
      console.log("No traffic summary data available");
      return;
    }

    const labels = data.map((item) => `${item.protocol} ${item.action}`);
    const counts = data.map((item) => item.count);
    const colors = data.map((item) =>
      item.action === "ACCEPT" ? "#10B981" : "#EF4444"
    );

    this.trafficChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Traffic Count",
            data: counts,
            backgroundColor: colors,
          },
        ],
      },
      options: {
        responsive: true,
        scales: { y: { beginAtZero: true } },
      },
    });
  }
};