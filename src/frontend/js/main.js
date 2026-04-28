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
    $("userInfo").textContent = payload
      ? `${payload.email || ""} (${payload.role || "?"})`
      : "logat";
    loadTickets();
  }
}

bindTabs();
initAuth(refreshAuthUI, refreshAuthUI);
initTickets();
refreshAuthUI();
