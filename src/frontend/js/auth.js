import { post, setToken, clearToken } from "./api.js";
import { $, showMsg, hideMsg } from "./ui.js";

export function initAuth(onLogin, onLogout) {
  $("loginBtn").addEventListener("click", async () => {
    const msg = $("loginMsg");
    hideMsg(msg);
    try {
      const data = await post("/auth/login", {
        email: $("loginEmail").value,
        password: $("loginPassword").value,
      });
      setToken(data.access_token);
      showMsg(msg, "Autentificat", true);
      onLogin?.();
    } catch (e) {
      showMsg(msg, e.message, false);
    }
  });

  $("regBtn").addEventListener("click", async () => {
    const msg = $("regMsg");
    hideMsg(msg);
    try {
      const data = await post("/auth/register", {
        email: $("regEmail").value,
        password: $("regPassword").value,
      });
      showMsg(msg, data.message || "OK", true);
    } catch (e) {
      showMsg(msg, e.message, false);
    }
  });

  $("forgotBtn").addEventListener("click", async () => {
    const msg = $("forgotMsg");
    hideMsg(msg);
    try {
      const data = await post("/auth/forgot-password", {
        email: $("forgotEmail").value,
      });
      showMsg(msg, data.message || "OK", true);
    } catch (e) {
      showMsg(msg, e.message, false);
    }
  });

  $("resetBtn").addEventListener("click", async () => {
    const msg = $("resetMsg");
    hideMsg(msg);
    try {
      const data = await post("/auth/reset-password", {
        reset_token: $("resetToken").value,
        new_password: $("resetPassword").value,
      });
      showMsg(msg, data.message || "OK", true);
    } catch (e) {
      showMsg(msg, e.message, false);
    }
  });

  $("logoutBtn").addEventListener("click", async () => {
    try { await post("/auth/logout"); } catch { /* tokenul e oricum invalidat local */ }
    clearToken();
    onLogout?.();
  });
}
