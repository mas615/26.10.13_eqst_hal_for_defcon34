const refreshClock = document.querySelector("#refresh-clock");
const leaderboardBody = document.querySelector("#leaderboard-body");
const submissionsBody = document.querySelector("#submissions-body");
const adminError = document.querySelector("#admin-error");

function escapeHtml(value) {
  return String(value ?? "—")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatTime(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("ko-KR", {
    timeZone: "Asia/Seoul",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(value));
}

function renderMetrics(summary) {
  document.querySelector("#metric-submissions").textContent = summary.submissions;
  document.querySelector("#metric-solves").textContent = summary.unique_solves;
  document.querySelector("#metric-agents").textContent = summary.agents;
  const rate = summary.submissions
    ? Math.round((summary.correct_submissions / summary.submissions) * 100)
    : 0;
  document.querySelector("#metric-rate").textContent = `${rate}%`;
}

function renderLeaderboard(rows, scorableChallenges) {
  if (!rows.length) {
    leaderboardBody.innerHTML =
      '<tr><td colspan="5" class="empty-cell">Waiting for submissions…</td></tr>';
    return;
  }
  leaderboardBody.innerHTML = rows
    .map(
      (row, index) => `
        <tr>
          <td><span class="rank rank-${Math.min(index + 1, 4)}">${index + 1}</span></td>
          <td class="agent-cell">${escapeHtml(row.agent_id)}</td>
          <td><strong class="solve-count">${row.solves}</strong> / ${scorableChallenges}</td>
          <td>${row.attempts}</td>
          <td>${formatTime(row.last_solve_at)}</td>
        </tr>
      `,
    )
    .join("");
}

function renderSubmittedValue(value) {
  if (value === null || value === undefined) {
    return '<span class="not-recorded">NOT RECORDED</span>';
  }
  return `<code class="submission-candidate">${escapeHtml(value)}</code>`;
}

function renderSubmissions(rows) {
  if (!rows.length) {
    submissionsBody.innerHTML =
      '<tr><td colspan="5" class="empty-cell">No submission data.</td></tr>';
    return;
  }
  submissionsBody.innerHTML = rows
    .map(
      (row) => `
        <tr>
          <td>${formatTime(row.created_at)}</td>
          <td class="agent-cell">${escapeHtml(row.agent_id)}</td>
          <td>${escapeHtml(row.challenge_id)}</td>
          <td>${renderSubmittedValue(row.submitted_value)}</td>
          <td>
            <span class="verdict ${row.correct ? "verdict-correct" : "verdict-wrong"}">
              ${row.correct ? "CORRECT" : "WRONG"}
            </span>
          </td>
        </tr>
      `,
    )
    .join("");
}

async function refreshDashboard() {
  try {
    const response = await fetch("/api/admin/overview", { cache: "no-store" });
    if (!response.ok) throw new Error(`dashboard unavailable (${response.status})`);
    const payload = await response.json();
    renderMetrics(payload.summary);
    renderLeaderboard(
      payload.leaderboard,
      payload.summary.scorable_challenges,
    );
    renderSubmissions(payload.recent);
    refreshClock.textContent = `LIVE · ${formatTime(payload.generated_at)}`;
    adminError.textContent = "";
  } catch (error) {
    refreshClock.textContent = "CONNECTION LOST";
    adminError.textContent = error.message;
  }
}

refreshDashboard();
setInterval(refreshDashboard, 3000);
