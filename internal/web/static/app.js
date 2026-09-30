// Veil web UI behavior. Pages work without this script; it adds search,
// shortcuts, reveal, and small conveniences.
(() => {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const csrf = $('meta[name="csrf"]')?.content || "";

  // Auto-lock countdown. The server ends the session on its own; this only
  // shows how long is left and moves to the locked page when time is up.
  const idle = Number($('meta[name="idle"]')?.content || 0);
  const out = $("#autolock");
  if (idle && out) {
    let left = idle;
    const tick = () => {
      out.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
      if (left-- <= 0) location.reload();
    };
    tick();
    setInterval(tick, 1000);
  }

  // Search filters rows as you type.
  const q = $("#q");
  if (q) {
    const rows = [...document.querySelectorAll("#secretList a.row")];
    const filter = () => {
      const term = q.value.trim().toLowerCase();
      let shown = 0;
      for (const r of rows) {
        const hit = !term || r.dataset.search.toLowerCase().includes(term);
        r.hidden = !hit;
        if (hit) shown++;
      }
      $("#noMatch").hidden = shown > 0;
    };
    q.addEventListener("input", filter);
    filter();
  }

  // Keyboard: / search, N new secret, Esc close drawer.
  document.addEventListener("keydown", (e) => {
    const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "");
    if (e.key === "Escape" && $(".drawer")) { location.href = "/secrets"; return; }
    if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "/" && q) { e.preventDefault(); q.focus(); }
    if (e.key.toLowerCase() === "n" && location.pathname.startsWith("/secrets") && !$(".drawer")) {
      e.preventDefault(); location.href = "/secrets/new";
    }
  });

  // Name field: capital letters, digits and _ only; suggest a host.
  const nameIn = $("#fName");
  const hosts = { ANTHROPIC: "api.anthropic.com", OPENAI: "api.openai.com", STRIPE: "api.stripe.com", GITHUB: "api.github.com",
    GITLAB: "gitlab.com", CLOUDFLARE: "api.cloudflare.com", VERCEL: "api.vercel.com", SLACK: "slack.com", LINEAR: "api.linear.app",
    NOTION: "api.notion.com", SENDGRID: "api.sendgrid.com", TWILIO: "api.twilio.com", AWS: "*.amazonaws.com" };
  const domains = $("#fDomains");
  const suggest = $("#suggest");
  const showSuggestion = () => {
    if (!suggest || !domains) return;
    const name = (nameIn?.value || "").toUpperCase();
    const key = Object.keys(hosts).find((k) => name.includes(k));
    const host = key && hosts[key];
    suggest.textContent = "";
    if (!host || domains.value.includes(host)) return;
    suggest.append(`Looks like a ${key[0] + key.slice(1).toLowerCase()} key. `);
    const b = document.createElement("button");
    b.type = "button"; b.className = "link"; b.textContent = `Add ${host}`;
    b.onclick = () => { domains.value = domains.value.trim() ? `${domains.value.trim()}, ${host}` : host; showSuggestion(); };
    suggest.append(b);
  };
  if (nameIn) {
    nameIn.addEventListener("input", () => {
      const pos = nameIn.selectionStart;
      nameIn.value = nameIn.value.toUpperCase().replace(/[\s.-]+/g, "_").replace(/[^A-Z0-9_]/g, "");
      nameIn.setSelectionRange(pos, pos);
      showSuggestion();
    });
  }
  domains?.addEventListener("input", showSuggestion);
  showSuggestion();

  // Show only the fields that apply to the chosen protection.
  const syncTier = () => {
    const t = document.querySelector('input[name="tier"]:checked')?.value;
    for (const el of document.querySelectorAll("[data-for]")) el.hidden = !el.dataset.for.split(" ").includes(t);
  };
  for (const r of document.querySelectorAll('input[name="tier"]')) r.addEventListener("change", syncTier);
  syncTier();

  // Delete: enable the button only when the name is typed exactly.
  for (const inp of document.querySelectorAll("[data-confirm]")) {
    const btn = inp.form.querySelector('button[type="submit"]');
    inp.addEventListener("input", () => { btn.disabled = inp.value !== inp.dataset.confirm; });
  }

  // Import: a Basic secret has no websites.
  for (const sel of document.querySelectorAll("select[data-row]")) {
    const dom = document.querySelector(`[data-domains="${sel.dataset.row}"]`);
    const sync = () => { dom.disabled = sel.value === "basic"; };
    sel.addEventListener("change", sync);
    sync();
  }

  // Copy commands.
  const copy = async (text, msg) => {
    try { await navigator.clipboard.writeText(text); toast(msg || "Copied"); }
    catch { toast("Copy was blocked. Select the text instead."); }
  };
  for (const el of document.querySelectorAll("[data-copy]")) {
    el.title = "Click to copy";
    el.addEventListener("click", () => copy(el.textContent.trim()));
  }

  function toast(msg) {
    let t = $(".toast.live");
    if (!t) {
      t = document.createElement("div");
      t.className = "toast live";
      t.setAttribute("role", "status");
      Object.assign(t.style, { position: "fixed", left: "50%", bottom: "24px", transform: "translateX(-50%)", zIndex: 30 });
      document.body.append(t);
    }
    t.textContent = msg;
    clearTimeout(t._h);
    t._h = setTimeout(() => t.remove(), 4000);
  }

  // Reveal: the server asks for Touch ID; the value is shown for 10 s.
  const veil = $("#veil");
  const revealBtn = $("#revealBtn");
  if (veil && revealBtn) {
    const masked = $("#masked"), timer = $("#timer");
    let hideTimer;
    const hide = () => {
      clearInterval(hideTimer);
      veil.classList.remove("open");
      masked.textContent = "••••••••••••••••";
      timer.textContent = "";
      revealBtn.textContent = "Reveal";
      revealBtn.onclick = reveal;
    };
    async function reveal() {
      revealBtn.disabled = true;
      revealBtn.textContent = "Confirm on your Mac…";
      try {
        const res = await fetch(`/secrets/${encodeURIComponent(veil.dataset.name)}/reveal`, {
          method: "POST", headers: { "X-CSRF-Token": csrf },
        });
        const body = await res.json();
        if (!res.ok) { toast(body.error || "Couldn't reveal it."); hide(); return; }
        veil.classList.add("open");
        masked.textContent = body.value;
        revealBtn.textContent = "Copy";
        revealBtn.onclick = async () => {
          await copy(body.value, "Copied. Veil clears the clipboard in 30 s if it still holds this.");
          setTimeout(async () => {
            try { if ((await navigator.clipboard.readText()) === body.value) await navigator.clipboard.writeText(""); } catch {}
          }, 30000);
        };
        let n = 10;
        timer.textContent = `Hides in ${n}s`;
        hideTimer = setInterval(() => { n--; timer.textContent = `Hides in ${n}s`; if (n <= 0) hide(); }, 1000);
      } catch {
        toast("Veil isn't responding. Is `veil ui` still running?");
        hide();
      } finally {
        revealBtn.disabled = false;
      }
    }
    revealBtn.onclick = reveal;
  }
})();
