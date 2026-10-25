// ====================================================================
// Cyber Threat Intelligence Charts Manager (Chart.js)
// ====================================================================

let attackChartInstance = null;
let timelineChartInstance = null;

const CYBER_PALETTE = [
  '#EF4444', // Red
  '#F97316', // Orange
  '#F59E0B', // Amber
  '#06B6D4', // Cyan
  '#8B5CF6', // Violet
  '#3B82F6', // Blue
  '#10B981', // Emerald
  '#EC4899'  // Pink
];

function initCharts() {
  Chart.defaults.color = '#94A3B8';
  Chart.defaults.font.family = "'Inter', sans-serif";
  Chart.defaults.font.size = 11;

  // 1. Attack Vectors Chart (Doughnut)
  const ctxAttack = document.getElementById('attackTypesChart');
  if (ctxAttack) {
    attackChartInstance = new Chart(ctxAttack, {
      type: 'doughnut',
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: CYBER_PALETTE,
          borderColor: '#0F172A',
          borderWidth: 2,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '68%',
        plugins: {
          legend: {
            position: 'right',
            labels: {
              boxWidth: 10,
              padding: 10,
              color: '#CBD5E1',
              font: { size: 10 }
            }
          },
          tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            borderColor: '#38BDF8',
            borderWidth: 1,
            titleColor: '#fff',
            bodyColor: '#38BDF8',
            padding: 10
          }
        }
      }
    });
  }

  // 2. Timeline Series Chart (Line / Bar)
  const ctxTimeline = document.getElementById('timelineChart');
  if (ctxTimeline) {
    timelineChartInstance = new Chart(ctxTimeline, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Alerts',
            data: [],
            borderColor: '#EF4444',
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointBackgroundColor: '#EF4444',
            pointRadius: 4
          },
          {
            label: 'Total Logs',
            data: [],
            borderColor: '#06B6D4',
            backgroundColor: 'rgba(6, 182, 212, 0.05)',
            borderWidth: 1.5,
            tension: 0.35,
            fill: true,
            pointBackgroundColor: '#06B6D4',
            pointRadius: 2
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: 'index',
          intersect: false
        },
        scales: {
          x: {
            grid: { color: 'rgba(51, 65, 85, 0.2)' },
            ticks: { color: '#64748B', maxTicksLimit: 6 }
          },
          y: {
            grid: { color: 'rgba(51, 65, 85, 0.2)' },
            ticks: { color: '#64748B', precision: 0 },
            beginAtZero: true
          }
        },
        plugins: {
          legend: {
            position: 'top',
            labels: { boxWidth: 8, padding: 8, color: '#CBD5E1', font: { size: 10 } }
          },
          tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            borderColor: '#06B6D4',
            borderWidth: 1,
            padding: 10
          }
        }
      }
    });
  }
}

function updateAttackTypesChart(breakdown) {
  if (!attackChartInstance) return;
  if (!breakdown || breakdown.length === 0) {
    attackChartInstance.data.labels = ['No Alerts'];
    attackChartInstance.data.datasets[0].data = [1];
    attackChartInstance.data.datasets[0].backgroundColor = ['#334155'];
    attackChartInstance.update();
    return;
  }

  attackChartInstance.data.labels = breakdown.map(item => item.name);
  attackChartInstance.data.datasets[0].data = breakdown.map(item => item.count);
  attackChartInstance.data.datasets[0].backgroundColor = CYBER_PALETTE.slice(0, breakdown.length);
  attackChartInstance.update();
}

function updateTimelineChart(timeline) {
  if (!timelineChartInstance) return;
  if (!timeline || !timeline.labels || timeline.labels.length === 0) {
    timelineChartInstance.data.labels = ['No Data'];
    timelineChartInstance.data.datasets[0].data = [0];
    timelineChartInstance.data.datasets[1].data = [0];
    timelineChartInstance.update();
    return;
  }

  timelineChartInstance.data.labels = timeline.labels.map(l => l.split(' ')[1] || l);
  timelineChartInstance.data.datasets[0].data = timeline.alerts;
  timelineChartInstance.data.datasets[1].data = timeline.events;
  timelineChartInstance.update();
}
