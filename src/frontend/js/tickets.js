import { get, post } from "./api.js";
import { $, showMsg, hideMsg, escapeHtml } from "./ui.js";

// in v2 frontendul reactiveaza escapeHtml; in v1 lasa raw pentru demo XSS
const safe = (v) =>
  window.__APP_VERSION__ === "v2" ? escapeHtml(v ?? "") : String(v ?? "");

function renderTicket(t) {
  const sev = (t.severity || "LOW").toUpperCase();
  const owner = t.created_by ?? t.owner_id ?? "?";
  const div = document.createElement("div");
  div.className = "ticket";
  div.innerHTML = `
    <div class="ticket-header">
      <div class="ticket-title">
        #${t.id ?? "?"} ${safe(t.title)}
        <span class="badge sev-${sev}">${sev}</span>
      </div>
      <div class="ticket-meta">${safe(t.status)} - owner ${owner}</div>
    </div>
    <div class="ticket-desc">${safe(t.description)}</div>
  `;
  return div;
}

export async function loadTickets() {
  const list = $("ticketsList");
  list.innerHTML = '<div class="empty">Loading...</div>';
  try {
    const tickets = await get("/tickets");
    if (!tickets || !tickets.length) {
      list.innerHTML = '<div class="empty">Niciun tichet.</div>';
      return;
    }
    list.innerHTML = "";
    tickets.forEach((t) => list.appendChild(renderTicket(t)));
  } catch (e) {
    list.innerHTML = `<div class="msg err">${escapeHtml(e.message)}</div>`;
  }
}

export function initTickets() {
  $("createBtn").addEventListener("click", async () => {
    const msg = $("createMsg");
    hideMsg(msg);
    try {
      const data = await post("/tickets", {
        title: $("newTitle").value,
        description: $("newDescription").value,
        severity: $("newSeverity").value,
      });
      showMsg(msg, data.message || "OK", true);
      $("newTitle").value = "";
      $("newDescription").value = "";
      loadTickets();
    } catch (e) {
      showMsg(msg, e.message, false);
    }
  });

  $("refreshBtn").addEventListener("click", loadTickets);
}
