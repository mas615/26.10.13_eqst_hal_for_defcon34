const challengeGrid = document.querySelector("#challenge-grid");
const runChallengeSelect = document.querySelector("#run-challenge");
const runForm = document.querySelector("#run-form");
const runButton = document.querySelector("#run-button");
const runResult = document.querySelector("#run-result");
const runAgentInput = document.querySelector("#run-agent");
const runOpenAIBaseUrl = document.querySelector("#run-openai-base-url");
const runOutput = document.querySelector("#run-output");
const runEnv = document.querySelector("#run-env");
const copyRunEnvButton = document.querySelector("#copy-run-env");
const challengeCount = document.querySelector("#challenge-count");
const publicLeaderboardBody = document.querySelector("#public-leaderboard-body");
const publicSubmissionsBody = document.querySelector("#public-submissions-body");
const challengeFirstBloodBody = document.querySelector(
  "#challenge-first-blood-body",
);
const leaderboardUpdated = document.querySelector("#leaderboard-updated");
const expandedLeaderboardAgents = new Set();

let currentRunEnv = "";

const categoryLabels = {
  web: "WEB",
  misc: "MISC",
  pwn: "PWN",
  crypto: "CRYPTO",
  rev: "REV",
  forensics: "FORENSICS",
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function commandFor(challenge) {
  if (!challenge.target) return null;
  if (["http", "https"].includes(challenge.protocol)) {
    return challenge.target;
  }
  const [host, port] = challenge.target.split(":");
  return `nc ${host} ${port}`;
}

async function copyText(value, button) {
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    await navigator.clipboard.writeText(value);
  } else {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }
  const previous = button.textContent;
  button.textContent = "COPIED";
  setTimeout(() => {
    button.textContent = previous;
  }, 1000);
}

function renderChallenges(challenges) {
  const openCount = challenges.filter((item) => item.status === "open").length;
  challengeCount.textContent = `${openCount} ONLINE · ${challenges.length} TOTAL`;
  challengeGrid.innerHTML = challenges
    .map((challenge, index) => {
      const attachments = challenge.attachments?.length
        ? challenge.attachments
            .map(
              (attachment) =>
                `<a class="attachment-link" href="${escapeHtml(attachment.url)}" download>
                   ↓ ${escapeHtml(attachment.name)}
                 </a>`,
            )
            .join("")
        : `<span class="no-attachment">NO ATTACHMENT</span>`;
      const targetCommand = commandFor(challenge);
      const targetLine = targetCommand
        ? `<div class="target-line">
             <code>${escapeHtml(targetCommand)}</code>
             <button class="copy-button" type="button" data-copy="${escapeHtml(targetCommand)}">
               COPY
             </button>
           </div>`
        : `<div class="target-line target-unavailable">
             <code>${escapeHtml(challenge.reason || "No live endpoint")}</code>
           </div>`;
      const statusClass =
        challenge.status === "open"
          ? "status-open"
          : challenge.status === "file-only"
            ? "status-file"
            : "status-blocked";
      const statusLabel =
        challenge.status === "open"
          ? "OPEN"
          : challenge.status === "file-only"
            ? "FILE"
            : "LOCKED";
      return `
        <article class="challenge-card challenge-card-${index + 1}">
          <div class="challenge-topline">
            <span class="challenge-index">${String(index + 1).padStart(2, "0")}</span>
            <span class="category category-${escapeHtml(challenge.category)}">
              ${escapeHtml(categoryLabels[challenge.category] || challenge.category)}
            </span>
            <span class="open-status ${statusClass}"><i></i>${statusLabel}</span>
          </div>
          <h3>${escapeHtml(challenge.name)}</h3>
          <p>${escapeHtml(challenge.description)}</p>
          ${targetLine}
          <div class="challenge-footer">
            <span class="attachment-list">${attachments}</span>
            <strong>${challenge.points} PTS</strong>
          </div>
        </article>
      `;
    })
    .join("");

  runChallengeSelect.replaceChildren();
  const initialOption = document.createElement("option");
  initialOption.value = "";
  initialOption.textContent = "Select one target";
  runChallengeSelect.append(initialOption);
  for (const challenge of challenges.filter((item) =>
    ["open", "file-only"].includes(item.status),
  )) {
    const option = document.createElement("option");
    option.value = challenge.id;
    option.textContent = `${challenge.name} · ${challenge.category}`;
    runChallengeSelect.append(option);
  }

  document.querySelectorAll(".copy-button").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        await copyText(button.dataset.copy, button);
      } catch {
        button.textContent = "COPY FAILED";
      }
    });
  });
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

function renderSolvedPreview(challenges) {
  if (!challenges.length) {
    return '<span class="solved-preview-empty">NO SOLVES YET</span>';
  }
  const visible = challenges
    .slice(0, 3)
    .map(
      (challenge) =>
        `<span class="solved-preview-chip">${escapeHtml(challenge.name)}</span>`,
    )
    .join("");
  const remaining = challenges.length - 3;
  return `
    <span class="solved-preview-list">${visible}</span>
    ${remaining > 0 ? `<span class="solved-preview-more">+${remaining}</span>` : ""}
  `;
}

function renderSolvedDetails(challenges) {
  if (!challenges.length) {
    return '<div class="solved-details-empty">아직 해결한 문제가 없습니다.</div>';
  }

  const grouped = new Map();
  for (const challenge of challenges) {
    const category = challenge.category || "other";
    if (!grouped.has(category)) grouped.set(category, []);
    grouped.get(category).push(challenge);
  }
  const categories = [
    ...Object.keys(categoryLabels).filter((category) => grouped.has(category)),
    ...[...grouped.keys()].filter((category) => !categoryLabels[category]),
  ];

  return `
    <div class="solved-details">
      <div class="solved-details-heading">
        <strong>${challenges.length} SOLVED</strong>
        <span>문제명 · 배점 · 최초 해결 시각</span>
      </div>
      ${categories
        .map(
          (category) => `
            <div class="solved-category-group">
              <span class="solved-category-label">
                ${escapeHtml(categoryLabels[category] || category.toUpperCase())}
              </span>
              <div class="solved-challenge-list">
                ${grouped
                  .get(category)
                  .map(
                    (challenge) => `
                      <span class="solved-challenge-card">
                        <strong>${escapeHtml(challenge.name)}</strong>
                        <small>${escapeHtml(challenge.points)} PTS · ${formatTime(challenge.first_solved_at)}</small>
                      </span>
                    `,
                  )
                  .join("")}
              </div>
            </div>
          `,
        )
        .join("")}
    </div>
  `;
}

function bindLeaderboardRows() {
  publicLeaderboardBody
    .querySelectorAll(".leaderboard-main-row")
    .forEach((row) => {
      row.addEventListener("click", () => {
        const detailRow = row.nextElementSibling;
        const toggle = row.querySelector(".solved-preview-button");
        const shouldExpand = detailRow.hidden;
        detailRow.hidden = !shouldExpand;
        row.classList.toggle("is-expanded", shouldExpand);
        toggle.setAttribute("aria-expanded", String(shouldExpand));
        if (shouldExpand) {
          expandedLeaderboardAgents.add(row.dataset.agentId);
        } else {
          expandedLeaderboardAgents.delete(row.dataset.agentId);
        }
      });
    });
}

function renderFirstBloodSolver(solver) {
  if (!solver) {
    return '<td><span class="first-blood-empty">—</span></td>';
  }
  const rank = Math.max(1, Math.min(3, Number(solver.rank) || 3));
  return `
    <td>
      <span class="first-blood-solver first-blood-rank-${rank}">
        <strong>${escapeHtml(solver.agent_id)}</strong>
        <small>${formatTime(solver.first_solved_at)}</small>
      </span>
    </td>
  `;
}

function renderChallengeFirstBloods(challenges) {
  if (!challenges.length) {
    challengeFirstBloodBody.innerHTML =
      '<tr><td colspan="4" class="empty-cell">No scorable challenges.</td></tr>';
    return;
  }
  challengeFirstBloodBody.innerHTML = challenges
    .map((challenge) => {
      const solvers = Array.isArray(challenge.solvers)
        ? challenge.solvers.slice(0, 3)
        : [];
      const podium = Array.from({ length: 3 }, (_, index) =>
        renderFirstBloodSolver(solvers[index]),
      ).join("");
      return `
        <tr>
          <td class="first-blood-challenge-cell">
            <div class="first-blood-challenge-title">
              <span class="category category-${escapeHtml(challenge.category)}">
                ${escapeHtml(categoryLabels[challenge.category] || challenge.category)}
              </span>
              <strong>${escapeHtml(challenge.name)}</strong>
            </div>
            <small>${escapeHtml(challenge.challenge_id)} · ${escapeHtml(challenge.points)} PTS</small>
          </td>
          ${podium}
        </tr>
      `;
    })
    .join("");
}

function renderPublicLeaderboard(payload) {
  const rows = payload.leaderboard;
  if (!rows.length) {
    publicLeaderboardBody.innerHTML =
      '<tr><td colspan="6" class="empty-cell">Waiting for MCP submissions…</td></tr>';
  } else {
    publicLeaderboardBody.innerHTML = rows
      .map((row, index) => {
        const solvedChallenges = Array.isArray(row.solved_challenges)
          ? row.solved_challenges
          : [];
        const isExpanded = expandedLeaderboardAgents.has(row.agent_id);
        const detailId = `leaderboard-details-${index}`;
        return `
          <tr
            class="leaderboard-main-row${isExpanded ? " is-expanded" : ""}"
            data-agent-id="${escapeHtml(row.agent_id)}"
          >
            <td><span class="rank rank-${Math.min(index + 1, 4)}">${index + 1}</span></td>
            <td class="agent-cell">${escapeHtml(row.agent_id)}</td>
            <td><strong class="solve-count">${row.solves}</strong> / ${payload.scorable_challenges}</td>
            <td class="solved-preview-cell">
              <button
                class="solved-preview-button"
                type="button"
                aria-expanded="${isExpanded}"
                aria-controls="${detailId}"
                aria-label="${escapeHtml(row.agent_id)} 해결 문제 상세"
              >
                ${renderSolvedPreview(solvedChallenges)}
                <span class="row-chevron" aria-hidden="true">⌄</span>
              </button>
            </td>
            <td>${row.attempts}</td>
            <td>${formatTime(row.last_solve_at)}</td>
          </tr>
          <tr
            id="${detailId}"
            class="leaderboard-detail-row"
            ${isExpanded ? "" : "hidden"}
          >
            <td colspan="6">${renderSolvedDetails(solvedChallenges)}</td>
          </tr>
        `;
      })
      .join("");
    bindLeaderboardRows();
  }
  leaderboardUpdated.textContent =
    `자동 갱신 · ${formatTime(payload.generated_at)} · ${payload.submissions} MCP submissions`;
  renderChallengeFirstBloods(payload.challenge_first_bloods || []);
  renderPublicSubmissions(payload.recent_submissions || []);
}

function renderPublicSubmissions(rows) {
  if (!rows.length) {
    publicSubmissionsBody.innerHTML =
      '<tr><td colspan="4" class="empty-cell">No submission data.</td></tr>';
    return;
  }
  publicSubmissionsBody.innerHTML = rows
    .map(
      (row) => `
        <tr>
          <td>${formatTime(row.created_at)}</td>
          <td class="agent-cell">${escapeHtml(row.agent_id)}</td>
          <td>${escapeHtml(row.challenge_id)}</td>
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

async function refreshPublicLeaderboard() {
  try {
    const response = await fetch("/api/leaderboard", { cache: "no-store" });
    if (!response.ok) throw new Error("leaderboard unavailable");
    renderPublicLeaderboard(await response.json());
  } catch {
    leaderboardUpdated.textContent = "리더보드를 불러오지 못했습니다.";
  }
}

async function loadChallenges() {
  try {
    const response = await fetch("/api/challenges", { cache: "no-store" });
    if (!response.ok) throw new Error("manifest unavailable");
    const payload = await response.json();
    renderChallenges(payload.challenges);
  } catch {
    challengeGrid.innerHTML =
      '<p class="error-line">Target manifest를 불러오지 못했습니다.</p>';
  }
}

function showRunResult(kind, title, detail) {
  runResult.className = `submit-result is-visible ${kind}`;
  runResult.innerHTML =
    `<strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span>`;
}

runForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  runButton.disabled = true;
  runButton.querySelector("span").textContent = "ISSUING…";
  runResult.className = "submit-result";
  runOutput.hidden = true;
  currentRunEnv = "";

  const payload = {
    user_id: runAgentInput.value.trim(),
    challenge_id: runChallengeSelect.value,
  };
  const modelEndpoint = runOpenAIBaseUrl.value.trim();
  if (modelEndpoint) payload.openai_base_url = modelEndpoint;

  try {
    const response = await fetch("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) {
      showRunResult(
        "wrong",
        "RUN REJECTED",
        result.message || result.error || "unknown error",
      );
      return;
    }
    currentRunEnv = result.env_file;
    runEnv.textContent = currentRunEnv;
    runOutput.hidden = false;
    showRunResult(
      "correct",
      "RUN ISSUED",
      `${result.run.run_id} · expires ${formatTime(result.run.expires_at)}`,
    );
    localStorage.setItem("halcompat-agent-id", payload.user_id);
    if (modelEndpoint) {
      localStorage.setItem("halcompat-openai-base-url", modelEndpoint);
    }
  } catch {
    showRunResult("wrong", "NETWORK ERROR", "run 발급 서버에 연결하지 못했습니다.");
  } finally {
    runButton.disabled = false;
    runButton.querySelector("span").textContent = "ISSUE PRACTICE RUN";
  }
});

copyRunEnvButton.addEventListener("click", async () => {
  if (!currentRunEnv) return;
  try {
    await copyText(currentRunEnv, copyRunEnvButton);
  } catch {
    copyRunEnvButton.textContent = "COPY FAILED";
  }
});

runAgentInput.value = localStorage.getItem("halcompat-agent-id") || "";
runOpenAIBaseUrl.value =
  localStorage.getItem("halcompat-openai-base-url") || "";
loadChallenges();
refreshPublicLeaderboard();
setInterval(refreshPublicLeaderboard, 5000);
