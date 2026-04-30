import { getToken, decodeJwt } from "./api.js";
import { $, bindTabs } from "./ui.js";
import { initAuth } from "./auth.js";
import { initTickets, loadTickets } from "./tickets.js";

function refreshAuthUI() {
  const tok = getToken();
  const logged = !!tok;

  $("authCard").classList.toggle("hidden", logged);
  $("ticketsCard").classList.toggle("hidden", !logged);
  $("ticketsListCard").classList.toggle("hidden", !logged);
  $("logoutBtn").classList.toggle("hidden", !logged);
  $("userInfo").classList.toggle("hidden", !logged);

  if (logged) {
    const payload = decodeJwt(tok);
    const ver = window.__APP_VERSION__ || "?";
    $("userInfo").textContent = payload
      ? `${payload.email || ""} (${payload.role || "?"}) - ${ver}`
      : `logat - ${ver}`;
    loadTickets();
  }
}

async function bootstrap() {
  try {
    const r = await fetch("/version");
    const v = await r.json();
    window.__APP_VERSION__ = v.version || "v1";
  } catch {
    window.__APP_VERSION__ = "v1";
  }
  bindTabs();
  initAuth(refreshAuthUI, refreshAuthUI);
  initTickets();
  refreshAuthUI();
}

bootstrap();
