export const $ = (id) => document.getElementById(id);

export function showMsg(el, text, ok = true) {
  el.textContent = text;
  el.className = "msg " + (ok ? "ok" : "err");
  el.classList.remove("hidden");
}

export function hideMsg(el) {
  el.classList.add("hidden");
}

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

export function bindTabs(container = document) {
  const tabs = container.querySelectorAll(".tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((x) => x.classList.remove("active"));
      container.querySelectorAll(".pane").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      const pane = $(`pane-${tab.dataset.tab}`);
      if (pane) pane.classList.add("active");
    });
  });
}
