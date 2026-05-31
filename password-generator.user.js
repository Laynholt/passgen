// ==UserScript==
// @name         Password Generator
// @namespace    local.password.generator
// @version      1.1.0
// @description  Deterministic password generator with per-site settings for Tampermonkey and Violentmonkey.
// @author       local
// @match        *://*/*
// @match        file:///*
// @updateURL    https://github.com/Laynholt/passgen/releases/latest/download/password-generator.user.js
// @downloadURL  https://github.com/Laynholt/passgen/releases/latest/download/password-generator.user.js
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_deleteValue
// @grant        GM_listValues
// @grant        GM_setClipboard
// @run-at       document-idle
// ==/UserScript==

(function initFactory(root, factory) {
  const api = factory(root);

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  if (root.document && !root.__passwordGeneratorUserscriptLoaded) {
    root.__passwordGeneratorUserscriptLoaded = true;
    api.init().catch((error) => console.error("[Password Generator]", error));
  }
})(typeof globalThis !== "undefined" ? globalThis : window, function createPasswordGenerator(root) {
  "use strict";

  const LOWER = "abcdefghijklmnopqrstuvwxyz";
  const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const DIGIT = "0123456789";
  const SYMB = "_-";

  const STORAGE_PREFIX = "pg-userscript:settings:";
  const GLOBAL_KEY = "pg-userscript:global";
  const INDEX_KEY = "pg-userscript:index";
  const FAB_POSITION_KEY = "pg-userscript:fab-position";
  const FAB_SIZE = 62;
  const FAB_MARGIN = 8;
  const DEFAULT_FAB_OFFSET = Object.freeze({ right: 14, bottom: 66 });
  const DRAG_THRESHOLD_PX = 6;

  const DEFAULT_SETTINGS = Object.freeze({
    master: "",
    length: 24,
    version: 1,
    counter: 0,
    alphabetMode: "sym",
    dontRemember: false,
    expanded: false
  });

  const QUICK_LENGTH_PRESETS = Object.freeze([
    Object.freeze({ label: "24", value: 24 }),
    Object.freeze({ label: "16", value: 16 })
  ]);

  const FAB_ICON_SVG = `
    <svg class="pg-fab-icon" viewBox="0 0 96 96" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="pgIconBody" x1="18" y1="39" x2="78" y2="87" gradientUnits="userSpaceOnUse">
          <stop offset="0" stop-color="#ffc342"/>
          <stop offset="0.48" stop-color="#ffad25"/>
          <stop offset="1" stop-color="#f59b18"/>
        </linearGradient>
        <filter id="pgIconShadow" x="-12" y="-12" width="120" height="120" color-interpolation-filters="sRGB">
          <feDropShadow dx="0" dy="4" stdDeviation="4" flood-color="#111827" flood-opacity="0.22"/>
        </filter>
      </defs>
      <g filter="url(#pgIconShadow)">
        <path data-part="shackle" d="M25 42V30C25 14 35 5 48 5s23 9 23 25v12H59V30c0-8-4-13-11-13s-11 5-11 13v12H25z" fill="#c7cfd9"/>
        <rect data-part="lock-body" x="16" y="39" width="64" height="47" rx="11" fill="url(#pgIconBody)"/>
        <path d="M17 51c5-7 19-10 38-10h17c5 0 8 3 8 8v9c-18 3-43 0-63-7z" fill="#ffcf5a" opacity="0.52"/>
        <circle data-part="keyhole" cx="48" cy="61" r="10" fill="#5e665c"/>
        <rect x="43" y="64" width="10" height="20" rx="5" fill="#5e665c"/>
      </g>
    </svg>
  `;

  const COMMON_MULTI_PART_SUFFIXES = new Set([
    "ac.uk",
    "co.jp",
    "co.kr",
    "co.nz",
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.mx",
    "com.tr",
    "com.ua",
    "com.sg",
    "com.hk",
    "edu.au",
    "gov.uk",
    "net.au",
    "net.uk",
    "org.au",
    "org.uk"
  ]);

  const utf8enc = (value) => new TextEncoder().encode(String(value));
  const normalizeDomain = (value) => String(value || "").trim().toLowerCase().normalize("NFC");
  const alphabetByMode = (mode) => (mode === "nosym" ? LOWER + UPPER + DIGIT : LOWER + UPPER + DIGIT + SYMB);

  function getCrypto() {
    const cryptoObject = root.crypto || (typeof crypto !== "undefined" ? crypto : null);
    if (!cryptoObject || !cryptoObject.subtle) {
      throw new Error("Web Crypto API is not available");
    }
    return cryptoObject;
  }

  function extractDomain(urlLike) {
    let hostname = "";

    try {
      hostname = new URL(String(urlLike || "")).hostname;
    } catch {
      return "";
    }

    return extractDomainFromHostname(hostname);
  }

  function extractDomainFromHostname(hostname) {
    const host = normalizeDomain(hostname)
      .replace(/\.$/, "")
      .replace(/^www\./, "");

    if (!host || host === "localhost" || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
      return host;
    }

    const labels = host.split(".").filter(Boolean);
    if (labels.length <= 2) return labels.join(".");

    const lastTwo = labels.slice(-2).join(".");
    if (COMMON_MULTI_PART_SUFFIXES.has(lastTwo) && labels.length >= 3) {
      return labels.slice(-3).join(".");
    }

    return labels.slice(-2).join(".");
  }

  async function pbkdf2(master, saltBytes, outLen = 32, iters = 300000) {
    const subtle = getCrypto().subtle;
    const key = await subtle.importKey("raw", utf8enc(master), { name: "PBKDF2" }, false, ["deriveBits"]);
    const bits = await subtle.deriveBits(
      { name: "PBKDF2", salt: saltBytes, iterations: iters, hash: "SHA-256" },
      key,
      outLen * 8
    );
    return new Uint8Array(bits);
  }

  async function tagForPolicy(password) {
    const data = new Uint8Array([...utf8enc("policy-fix"), ...utf8enc(password)]);
    const digest = await getCrypto().subtle.digest("SHA-256", data);
    return new Uint8Array(digest);
  }

  async function* byteStream(seed) {
    for (const byte of seed) yield byte;

    let counter = 1;
    while (true) {
      const block = new Uint8Array([
        ...seed,
        (counter >>> 24) & 255,
        (counter >>> 16) & 255,
        (counter >>> 8) & 255,
        counter & 255
      ]);
      const digest = await getCrypto().subtle.digest("SHA-256", block);
      yield* new Uint8Array(digest);
      counter += 1;
    }
  }

  async function mapBytesToPasswordRejection(seed, length, alphabet) {
    const base = alphabet.length;
    if (base < 2) throw new Error("Alphabet must contain at least two symbols");

    const limit = Math.floor(256 / base) * base;
    const output = [];
    const stream = byteStream(seed);

    while (output.length < length) {
      const { value: byte } = await stream.next();
      if (byte < limit) output.push(alphabet[byte % base]);
    }

    return output.join("");
  }

  function requiredSetsForAlphabet(alphabet) {
    const required = [];
    if ([...LOWER].some((char) => alphabet.includes(char))) required.push(LOWER);
    if ([...UPPER].some((char) => alphabet.includes(char))) required.push(UPPER);
    if ([...DIGIT].some((char) => alphabet.includes(char))) required.push(DIGIT);

    const symbols = [...SYMB].filter((char) => alphabet.includes(char)).join("");
    if (symbols) required.push(symbols);

    return required;
  }

  async function ensurePolicy(password, alphabet, requireSets) {
    const chars = [...password];
    const tag = await tagForPolicy(password);
    let cursor = 0;
    const nextByte = () => tag[cursor++ % tag.length];
    const hasAny = (set) => chars.some((char) => set.includes(char));

    for (const set of requireSets) {
      if (!hasAny(set)) {
        const pos = nextByte() % chars.length;
        const char = set[nextByte() % set.length];
        chars[pos] = char;
      }
    }

    if (!chars.every((char) => alphabet.includes(char))) {
      throw new Error("Generated password contains a symbol outside the selected alphabet");
    }

    return chars.join("");
  }

  async function generateSitePassword({
    master,
    site,
    length = 24,
    version = 1,
    counter = 0,
    alphabet,
    enforcePolicy = true,
    iterations = 300000
  }) {
    const siteNorm = normalizeDomain(site);
    const seed = await pbkdf2(
      master,
      utf8enc(`pw:${siteNorm}|v=${version}|c=${counter}`),
      Math.max(32, length),
      iterations
    );
    let password = await mapBytesToPasswordRejection(seed, length, alphabet);

    if (enforcePolicy) {
      const required = requiredSetsForAlphabet(alphabet);
      if (required.length) password = await ensurePolicy(password, alphabet, required);
    }

    return password;
  }

  function clampInteger(value, min, max, fallback) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(min, Math.min(max, parsed));
  }

  function normalizeViewport(viewport) {
    return {
      width: Math.max(1, Number(viewport?.width) || 1),
      height: Math.max(1, Number(viewport?.height) || 1)
    };
  }

  function currentViewport() {
    const doc = root.document?.documentElement;
    return normalizeViewport({
      width: root.innerWidth || doc?.clientWidth || 1,
      height: root.innerHeight || doc?.clientHeight || 1
    });
  }

  function clampFabPosition(position, viewport, size = FAB_SIZE, margin = FAB_MARGIN) {
    const safeViewport = normalizeViewport(viewport);
    const maxX = Math.max(margin, safeViewport.width - size - margin);
    const maxY = Math.max(margin, safeViewport.height - size - margin);
    const rawX = Number(position?.x);
    const rawY = Number(position?.y);

    return {
      x: Math.round(Math.min(Math.max(Number.isFinite(rawX) ? rawX : margin, margin), maxX)),
      y: Math.round(Math.min(Math.max(Number.isFinite(rawY) ? rawY : margin, margin), maxY))
    };
  }

  function defaultFabPosition(viewport, size = FAB_SIZE) {
    const safeViewport = normalizeViewport(viewport);
    return clampFabPosition({
      x: safeViewport.width - DEFAULT_FAB_OFFSET.right - size,
      y: safeViewport.height - DEFAULT_FAB_OFFSET.bottom - size
    }, safeViewport, size);
  }

  function resolveFabPosition(value, viewport) {
    if (value && Number.isFinite(Number(value.x)) && Number.isFinite(Number(value.y))) {
      return clampFabPosition(value, viewport);
    }

    return defaultFabPosition(viewport);
  }

  function toStoredSettings(settings) {
    return {
      length: clampInteger(settings.length, 8, 64, DEFAULT_SETTINGS.length),
      version: clampInteger(settings.version, 0, 999, DEFAULT_SETTINGS.version),
      counter: clampInteger(settings.counter, 0, 10000, DEFAULT_SETTINGS.counter),
      alphabetMode: settings.alphabetMode === "nosym" ? "nosym" : "sym",
      dontRemember: Boolean(settings.dontRemember),
      expanded: Boolean(settings.expanded),
      master: settings.dontRemember ? "" : String(settings.master || "")
    };
  }

  function storageKeyForDomain(domain) {
    return STORAGE_PREFIX + normalizeDomain(domain);
  }

  function hasLocalStorage() {
    try {
      return Boolean(root.localStorage);
    } catch {
      return false;
    }
  }

  async function getValue(key, fallback) {
    try {
      if (typeof root.GM_getValue === "function") return root.GM_getValue(key, fallback);
      if (root.GM && typeof root.GM.getValue === "function") return await root.GM.getValue(key, fallback);
      if (hasLocalStorage()) {
        const raw = root.localStorage.getItem(key);
        return raw == null ? fallback : JSON.parse(raw);
      }
    } catch (error) {
      console.warn("[Password Generator] storage read failed", error);
    }
    return fallback;
  }

  async function setValue(key, value) {
    try {
      if (typeof root.GM_setValue === "function") {
        root.GM_setValue(key, value);
        return;
      }
      if (root.GM && typeof root.GM.setValue === "function") {
        await root.GM.setValue(key, value);
        return;
      }
      if (hasLocalStorage()) root.localStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
      console.warn("[Password Generator] storage write failed", error);
    }
  }

  async function deleteValue(key) {
    try {
      if (typeof root.GM_deleteValue === "function") {
        root.GM_deleteValue(key);
        return;
      }
      if (root.GM && typeof root.GM.deleteValue === "function") {
        await root.GM.deleteValue(key);
        return;
      }
      if (hasLocalStorage()) root.localStorage.removeItem(key);
    } catch (error) {
      console.warn("[Password Generator] storage delete failed", error);
    }
  }

  async function listValues() {
    try {
      if (typeof root.GM_listValues === "function") return root.GM_listValues();
      if (root.GM && typeof root.GM.listValues === "function") return await root.GM.listValues();
      if (hasLocalStorage()) {
        return Array.from({ length: root.localStorage.length }, (_, index) => root.localStorage.key(index));
      }
    } catch (error) {
      console.warn("[Password Generator] storage list failed", error);
    }
    return await getValue(INDEX_KEY, []);
  }

  async function rememberKey(key) {
    const index = new Set(await getValue(INDEX_KEY, []));
    index.add(key);
    await setValue(INDEX_KEY, [...index]);
  }

  async function saveDomainSettings(domain, settings) {
    const key = storageKeyForDomain(domain);
    await setValue(key, toStoredSettings(settings));
    await rememberKey(key);
  }

  async function saveGlobalSettings(settings) {
    await setValue(GLOBAL_KEY, toStoredSettings(settings));
    await rememberKey(GLOBAL_KEY);
  }

  async function loadSettingsForDomain(domain) {
    const globalSettings = await getValue(GLOBAL_KEY, {});
    const domainSettings = await getValue(storageKeyForDomain(domain), {});
    return {
      ...DEFAULT_SETTINGS,
      ...globalSettings,
      ...domainSettings
    };
  }

  function setStatus(state, text, tone) {
    if (!state.status) return;
    state.status.textContent = text || "";
    state.status.dataset.tone = tone || "neutral";
  }

  function setExpanded(state, expanded) {
    state.expanded = Boolean(expanded);
    state.advanced.hidden = !state.expanded;
    state.expandButton.textContent = state.expanded ? "Скрыть параметры" : "Параметры";
  }

  function syncQuickLengthButtons(state) {
    const currentLength = clampInteger(state.length.value, 8, 64, DEFAULT_SETTINGS.length);
    for (const button of state.quickLengthButtons) {
      const active = Number(button.dataset.length) === currentLength;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", active ? "true" : "false");
    }
  }

  function readUiSettings(state) {
    return {
      master: state.master.value,
      length: state.length.value,
      version: state.version.value,
      counter: state.counter.value,
      alphabetMode: state.alphabet.value,
      dontRemember: state.dontRemember.checked,
      expanded: state.expanded
    };
  }

  function applyUiSettings(state, settings) {
    state.master.value = settings.master || "";
    state.length.value = settings.length ?? DEFAULT_SETTINGS.length;
    state.version.value = settings.version ?? DEFAULT_SETTINGS.version;
    state.counter.value = settings.counter ?? DEFAULT_SETTINGS.counter;
    state.alphabet.value = settings.alphabetMode === "nosym" ? "nosym" : "sym";
    state.dontRemember.checked = Boolean(settings.dontRemember);
    setExpanded(state, Boolean(settings.expanded));
    syncQuickLengthButtons(state);
  }

  async function loadCurrentDomainIntoUi(state) {
    const domain = extractDomain(root.location ? root.location.href : "");
    state.domain.value = domain;
    const settings = await loadSettingsForDomain(domain);
    applyUiSettings(state, settings);
  }

  async function copyText(text) {
    if (typeof root.GM_setClipboard === "function") {
      root.GM_setClipboard(text);
      return;
    }

    if (root.navigator && root.navigator.clipboard) {
      await root.navigator.clipboard.writeText(text);
      return;
    }

    const textarea = root.document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    root.document.body.appendChild(textarea);
    textarea.select();
    root.document.execCommand("copy");
    textarea.remove();
  }

  async function exportSettings() {
    const keys = (await listValues()).filter((key) => key === GLOBAL_KEY || key === INDEX_KEY || key === FAB_POSITION_KEY || key.startsWith(STORAGE_PREFIX));
    const output = {};

    for (const key of keys) {
      output[key] = await getValue(key, null);
    }

    return JSON.stringify(output, null, 2);
  }

  async function importSettings(text) {
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Import file must contain a JSON object");
    }

    for (const [key, value] of Object.entries(parsed)) {
      if (key === GLOBAL_KEY || key === INDEX_KEY || key === FAB_POSITION_KEY || key.startsWith(STORAGE_PREFIX)) {
        await setValue(key, value);
        if (key !== INDEX_KEY) await rememberKey(key);
      }
    }
  }

  async function resetSettings() {
    const keys = (await listValues()).filter((key) => key === GLOBAL_KEY || key === INDEX_KEY || key === FAB_POSITION_KEY || key.startsWith(STORAGE_PREFIX));
    for (const key of keys) {
      await deleteValue(key);
    }
  }

  function applyFabPosition(state, position) {
    const next = clampFabPosition(position, currentViewport());
    state.fabPosition = next;
    state.fab.style.left = `${next.x}px`;
    state.fab.style.top = `${next.y}px`;
    state.fab.style.right = "auto";
    state.fab.style.bottom = "auto";
    positionPanelNearFab(state);
  }

  async function loadFabPosition(state) {
    const saved = await getValue(FAB_POSITION_KEY, null);
    applyFabPosition(state, resolveFabPosition(saved, currentViewport()));
  }

  async function saveFabPosition(state) {
    await setValue(FAB_POSITION_KEY, state.fabPosition);
    await rememberKey(FAB_POSITION_KEY);
  }

  function positionPanelNearFab(state) {
    if (!state.panel || state.panel.hidden) return;

    const viewport = currentViewport();
    const fabRect = state.fab.getBoundingClientRect();
    const panelRect = state.panel.getBoundingClientRect();
    const panelWidth = panelRect.width || Math.min(360, viewport.width - 24);
    const panelHeight = panelRect.height || Math.min(720, viewport.height - 36);
    const margin = 12;
    const maxX = Math.max(margin, viewport.width - panelWidth - margin);
    const maxY = Math.max(margin, viewport.height - panelHeight - margin);
    const centeredX = fabRect.left + fabRect.width / 2 - panelWidth / 2;
    const aboveY = fabRect.top - panelHeight - margin;
    const belowY = fabRect.bottom + margin;
    const preferredY = aboveY >= margin ? aboveY : belowY;

    state.panel.style.left = `${Math.round(Math.min(Math.max(centeredX, margin), maxX))}px`;
    state.panel.style.top = `${Math.round(Math.min(Math.max(preferredY, margin), maxY))}px`;
    state.panel.style.right = "auto";
    state.panel.style.bottom = "auto";
  }

  function downloadText(filename, text) {
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = root.document.createElement("a");
    link.href = url;
    link.download = filename;
    root.document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function createUi() {
    const host = root.document.createElement("div");
    host.id = "pg-userscript-root";
    root.document.documentElement.appendChild(host);

    const shadow = host.attachShadow({ mode: "open" });
    shadow.innerHTML = `
      <style>
        :host {
          --pg-bg: #ffffff;
          --pg-text: #1f2328;
          --pg-muted: #667085;
          --pg-border: #d0d7de;
          --pg-accent: #0b74d5;
          --pg-accent-hover: #095fb0;
          --pg-green: #16833a;
          --pg-red: #b42318;
          color-scheme: light;
          font-family: system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
        }
        * { box-sizing: border-box; }
        .pg-fab {
          position: fixed;
          right: 14px;
          bottom: 66px;
          z-index: 2147483647;
          width: 62px;
          height: 62px;
          border: 0;
          border-radius: 10px;
          display: grid;
          place-items: center;
          background: transparent;
          color: #fff;
          cursor: pointer;
          box-shadow: none;
          padding: 0;
          touch-action: none;
          user-select: none;
        }
        .pg-fab.is-dragging { cursor: grabbing; }
        .pg-fab-icon {
          width: 62px;
          height: 62px;
          display: block;
        }
        .pg-sr-only {
          position: absolute;
          width: 1px;
          height: 1px;
          padding: 0;
          margin: -1px;
          overflow: hidden;
          clip: rect(0, 0, 0, 0);
          white-space: nowrap;
          border: 0;
        }
        .pg-panel {
          position: fixed;
          right: 18px;
          bottom: 132px;
          z-index: 2147483647;
          width: min(360px, calc(100vw - 24px));
          max-height: min(720px, calc(100vh - 36px));
          overflow: auto;
          border: 1px solid var(--pg-border);
          border-radius: 8px;
          background: var(--pg-bg);
          color: var(--pg-text);
          box-shadow: 0 18px 48px rgba(0,0,0,.22);
          padding: 14px;
        }
        .pg-panel[hidden] { display: none; }
        .pg-header {
          display: grid;
          grid-template-columns: 1fr auto;
          gap: 8px;
          align-items: center;
          margin-bottom: 12px;
        }
        .pg-title {
          margin: 0;
          font-size: 15px;
          font-weight: 700;
          letter-spacing: 0;
        }
        .pg-close {
          width: 32px;
          height: 32px;
          border: 1px solid var(--pg-border);
          border-radius: 6px;
          background: #f6f8fa;
          color: var(--pg-text);
          cursor: pointer;
          font-size: 18px;
          line-height: 1;
        }
        .pg-field { margin-bottom: 10px; }
        .pg-label {
          display: block;
          margin-bottom: 5px;
          font-size: 12px;
          font-weight: 650;
        }
        .pg-input,
        .pg-select {
          width: 100%;
          min-height: 36px;
          border: 1px solid var(--pg-border);
          border-radius: 6px;
          background: #fff;
          color: var(--pg-text);
          padding: 7px 9px;
          font: 13px/1.35 system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
        }
        .pg-input:focus,
        .pg-select:focus {
          outline: 2px solid rgba(11,116,213,.22);
          border-color: var(--pg-accent);
        }
        .pg-master-row {
          display: grid;
          grid-template-columns: 1fr auto;
          gap: 8px;
        }
        .pg-small-button {
          min-width: 42px;
          min-height: 36px;
          border: 1px solid var(--pg-border);
          border-radius: 6px;
          background: #f6f8fa;
          color: var(--pg-text);
          cursor: pointer;
          font-size: 12px;
        }
        .pg-actions {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 8px;
          margin: 10px 0;
        }
        .pg-button {
          min-height: 38px;
          border: 0;
          border-radius: 6px;
          background: var(--pg-accent);
          color: #fff;
          cursor: pointer;
          font-weight: 700;
          font-size: 13px;
        }
        .pg-button:hover { background: var(--pg-accent-hover); }
        .pg-button:disabled {
          opacity: .55;
          cursor: not-allowed;
        }
        .pg-copy { background: var(--pg-green); }
        .pg-quick-length {
          display: grid;
          grid-template-columns: auto 1fr 1fr;
          gap: 7px;
          align-items: center;
          margin: 4px 0 10px;
        }
        .pg-quick-label {
          color: var(--pg-muted);
          font-size: 12px;
          white-space: nowrap;
        }
        .pg-preset {
          min-height: 32px;
          border: 1px solid var(--pg-border);
          border-radius: 6px;
          background: #f6f8fa;
          color: var(--pg-text);
          cursor: pointer;
          font-size: 12px;
          font-weight: 700;
        }
        .pg-preset.is-active {
          border-color: var(--pg-accent);
          background: var(--pg-accent);
          color: #fff;
        }
        .pg-expand {
          width: 100%;
          margin-bottom: 10px;
          background: #f6f8fa;
          color: var(--pg-text);
          border: 1px solid var(--pg-border);
        }
        .pg-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 9px;
        }
        .pg-check {
          display: flex;
          gap: 8px;
          align-items: center;
          margin: 4px 0 10px;
          font-size: 12px;
          color: var(--pg-text);
        }
        .pg-check input { width: 15px; height: 15px; }
        .pg-output {
          min-height: 42px;
          border: 1px solid var(--pg-border);
          border-radius: 6px;
          background: #f6f8fa;
          padding: 9px;
          overflow-wrap: anywhere;
          font: 13px/1.35 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
        }
        .pg-status {
          min-height: 18px;
          margin-top: 7px;
          color: var(--pg-muted);
          font-size: 12px;
          text-align: center;
        }
        .pg-status[data-tone="ok"] { color: var(--pg-green); }
        .pg-status[data-tone="error"] { color: var(--pg-red); }
        .pg-tools {
          display: grid;
          grid-template-columns: 1fr 1fr 1fr;
          gap: 7px;
          margin-top: 10px;
        }
        .pg-file { display: none; }
        @media (prefers-color-scheme: dark) {
          :host {
            --pg-bg: #202124;
            --pg-text: #f1f5f9;
            --pg-muted: #b7c0cc;
            --pg-border: #4b5563;
            --pg-accent: #1d8cf8;
            --pg-accent-hover: #1573c9;
            color-scheme: dark;
          }
          .pg-input,
          .pg-select {
            background: #2b2f36;
            color: var(--pg-text);
          }
          .pg-close,
          .pg-small-button,
          .pg-preset,
          .pg-expand,
          .pg-output {
            background: #2b2f36;
            color: var(--pg-text);
          }
          .pg-preset.is-active {
            background: var(--pg-accent);
            color: #fff;
          }
        }
      </style>
      <button class="pg-fab" type="button" title="Password Generator">${FAB_ICON_SVG}<span class="pg-sr-only">Password Generator</span></button>
      <section class="pg-panel" hidden aria-label="Password Generator">
        <div class="pg-header">
          <h2 class="pg-title">Password Generator</h2>
          <button class="pg-close" type="button" title="Закрыть">×</button>
        </div>

        <div class="pg-field">
          <label class="pg-label" for="pg-domain">Сайт / домен</label>
          <input id="pg-domain" class="pg-input" type="text" autocomplete="off" spellcheck="false">
        </div>

        <div class="pg-field">
          <label class="pg-label" for="pg-master">Мастер-ключ</label>
          <div class="pg-master-row">
            <input id="pg-master" class="pg-input" type="password" autocomplete="off" spellcheck="false">
            <button class="pg-small-button pg-show" type="button">Show</button>
          </div>
        </div>

        <div class="pg-quick-length" aria-label="Быстрый выбор длины">
          <span class="pg-quick-label">Длина</span>
          ${QUICK_LENGTH_PRESETS.map((preset) => `<button class="pg-preset" type="button" data-length="${preset.value}" aria-pressed="false">${preset.label}</button>`).join("")}
        </div>

        <button class="pg-button pg-expand" type="button">Параметры</button>

        <div class="pg-advanced" hidden>
          <div class="pg-grid">
            <div class="pg-field">
              <label class="pg-label" for="pg-length">Длина</label>
              <input id="pg-length" class="pg-input" type="number" min="8" max="64" step="1">
            </div>
            <div class="pg-field">
              <label class="pg-label" for="pg-version">Версия</label>
              <input id="pg-version" class="pg-input" type="number" min="0" max="999" step="1">
            </div>
            <div class="pg-field">
              <label class="pg-label" for="pg-counter">Счетчик</label>
              <input id="pg-counter" class="pg-input" type="number" min="0" max="10000" step="1">
            </div>
            <div class="pg-field">
              <label class="pg-label" for="pg-alphabet">Алфавит</label>
              <select id="pg-alphabet" class="pg-select">
                <option value="sym">a-z A-Z 0-9 _ -</option>
                <option value="nosym">только a-z A-Z 0-9</option>
              </select>
            </div>
          </div>

          <label class="pg-check">
            <input id="pg-dont-remember" type="checkbox">
            <span>Не запоминать мастер-ключ</span>
          </label>

          <div class="pg-tools">
            <button class="pg-small-button pg-export" type="button">Экспорт</button>
            <button class="pg-small-button pg-import" type="button">Импорт</button>
            <button class="pg-small-button pg-reset" type="button">Сброс</button>
          </div>
          <input class="pg-file" type="file" accept="application/json">
        </div>

        <div class="pg-actions">
          <button class="pg-button pg-generate" type="button">Сгенерировать</button>
          <button class="pg-button pg-copy" type="button" disabled>Скопировать</button>
        </div>

        <div class="pg-output" aria-live="polite"></div>
        <div class="pg-status" data-tone="neutral"></div>
      </section>
    `;

    return {
      host,
      shadow,
      fab: shadow.querySelector(".pg-fab"),
      panel: shadow.querySelector(".pg-panel"),
      close: shadow.querySelector(".pg-close"),
      domain: shadow.querySelector("#pg-domain"),
      master: shadow.querySelector("#pg-master"),
      showMaster: shadow.querySelector(".pg-show"),
      expandButton: shadow.querySelector(".pg-expand"),
      advanced: shadow.querySelector(".pg-advanced"),
      length: shadow.querySelector("#pg-length"),
      quickLengthButtons: Array.from(shadow.querySelectorAll(".pg-preset")),
      version: shadow.querySelector("#pg-version"),
      counter: shadow.querySelector("#pg-counter"),
      alphabet: shadow.querySelector("#pg-alphabet"),
      dontRemember: shadow.querySelector("#pg-dont-remember"),
      generate: shadow.querySelector(".pg-generate"),
      copy: shadow.querySelector(".pg-copy"),
      output: shadow.querySelector(".pg-output"),
      status: shadow.querySelector(".pg-status"),
      exportButton: shadow.querySelector(".pg-export"),
      importButton: shadow.querySelector(".pg-import"),
      resetButton: shadow.querySelector(".pg-reset"),
      file: shadow.querySelector(".pg-file"),
      expanded: false,
      fabPosition: null,
      suppressNextFabClick: false,
      lastPassword: ""
    };
  }

  function bindFabDrag(state) {
    let drag = null;

    state.fab.addEventListener("pointerdown", (event) => {
      if (event.button != null && event.button !== 0) return;

      const rect = state.fab.getBoundingClientRect();
      drag = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        originX: rect.left,
        originY: rect.top,
        active: false
      };
      state.fab.setPointerCapture?.(event.pointerId);
    });

    state.fab.addEventListener("pointermove", (event) => {
      if (!drag || event.pointerId !== drag.pointerId) return;

      const dx = event.clientX - drag.startX;
      const dy = event.clientY - drag.startY;
      const distance = Math.hypot(dx, dy);

      if (!drag.active && distance < DRAG_THRESHOLD_PX) return;

      drag.active = true;
      state.fab.classList.add("is-dragging");
      event.preventDefault();
      applyFabPosition(state, {
        x: drag.originX + dx,
        y: drag.originY + dy
      });
    });

    const finishDrag = async (event) => {
      if (!drag || event.pointerId !== drag.pointerId) return;

      const wasDragging = drag.active;
      drag = null;
      state.fab.classList.remove("is-dragging");
      state.fab.releasePointerCapture?.(event.pointerId);

      if (wasDragging) {
        state.suppressNextFabClick = true;
        event.preventDefault();
        await saveFabPosition(state);
      }
    };

    state.fab.addEventListener("pointerup", finishDrag);
    state.fab.addEventListener("pointercancel", finishDrag);

    root.addEventListener?.("resize", () => {
      applyFabPosition(state, state.fabPosition || defaultFabPosition(currentViewport()));
    }, { passive: true });
  }

  async function bindUi(state) {
    await loadFabPosition(state);
    bindFabDrag(state);
    await loadCurrentDomainIntoUi(state);

    state.fab.addEventListener("click", async () => {
      if (state.suppressNextFabClick) {
        state.suppressNextFabClick = false;
        return;
      }

      state.panel.hidden = !state.panel.hidden;
      if (!state.panel.hidden && !state.domain.value) await loadCurrentDomainIntoUi(state);
      positionPanelNearFab(state);
    });

    state.close.addEventListener("click", () => {
      state.panel.hidden = true;
    });

    state.showMaster.addEventListener("click", () => {
      const hidden = state.master.type === "password";
      state.master.type = hidden ? "text" : "password";
      state.showMaster.textContent = hidden ? "Hide" : "Show";
    });

    state.expandButton.addEventListener("click", async () => {
      setExpanded(state, !state.expanded);
      const settings = readUiSettings(state);
      await saveGlobalSettings(settings);
    });

    for (const button of state.quickLengthButtons) {
      button.addEventListener("click", async () => {
        state.length.value = button.dataset.length || String(DEFAULT_SETTINGS.length);
        syncQuickLengthButtons(state);
        await saveGlobalSettings(readUiSettings(state));
      });
    }

    state.length.addEventListener("input", () => {
      syncQuickLengthButtons(state);
    });

    state.generate.addEventListener("click", async () => {
      const domain = normalizeDomain(state.domain.value);
      const master = state.master.value;

      if (!domain) {
        setStatus(state, "Введите домен.", "error");
        state.domain.focus();
        return;
      }

      if (!master) {
        setStatus(state, "Введите мастер-ключ. Встроенного дефолтного ключа нет.", "error");
        state.master.focus();
        return;
      }

      const settings = toStoredSettings(readUiSettings(state));
      const length = settings.length;

      try {
        setStatus(state, "Генерация...", "neutral");
        const password = await generateSitePassword({
          master,
          site: domain,
          length,
          version: settings.version,
          counter: settings.counter,
          alphabet: alphabetByMode(settings.alphabetMode),
          enforcePolicy: true,
          iterations: 300000
        });

        state.lastPassword = password;
        state.output.textContent = password;
        state.copy.disabled = false;
        await saveGlobalSettings(settings);
        await saveDomainSettings(domain, settings);
        setStatus(state, "Настройки сохранены.", "ok");
      } catch (error) {
        console.error("[Password Generator]", error);
        setStatus(state, `Ошибка: ${error.message}`, "error");
      }
    });

    state.copy.addEventListener("click", async () => {
      if (!state.lastPassword) return;

      try {
        await copyText(state.lastPassword);
        setStatus(state, "Скопировано.", "ok");
      } catch (error) {
        console.error("[Password Generator]", error);
        setStatus(state, "Не удалось скопировать.", "error");
      }
    });

    state.exportButton.addEventListener("click", async () => {
      try {
        downloadText("password_generator_userscript_settings.json", await exportSettings());
        setStatus(state, "Экспорт подготовлен.", "ok");
      } catch (error) {
        console.error("[Password Generator]", error);
        setStatus(state, "Ошибка экспорта.", "error");
      }
    });

    state.importButton.addEventListener("click", () => {
      state.file.click();
    });

    state.file.addEventListener("change", async () => {
      const file = state.file.files && state.file.files[0];
      state.file.value = "";
      if (!file) return;

      try {
        await importSettings(await file.text());
        await loadCurrentDomainIntoUi(state);
        setStatus(state, "Импорт выполнен.", "ok");
      } catch (error) {
        console.error("[Password Generator]", error);
        setStatus(state, "Ошибка импорта JSON.", "error");
      }
    });

    state.resetButton.addEventListener("click", async () => {
      if (!root.confirm("Удалить сохраненные настройки Password Generator?")) return;

      await resetSettings();
      await loadCurrentDomainIntoUi(state);
      state.output.textContent = "";
      state.lastPassword = "";
      state.copy.disabled = true;
      setStatus(state, "Настройки сброшены.", "ok");
    });
  }

  async function init() {
    if (!root.document || root.document.getElementById("pg-userscript-root")) return;
    const state = createUi();
    await bindUi(state);
  }

  return {
    init,
    __test: {
      DEFAULT_SETTINGS,
      FAB_ICON_SVG,
      FAB_POSITION_KEY,
      QUICK_LENGTH_PRESETS,
      alphabetByMode,
      clampFabPosition,
      defaultFabPosition,
      extractDomain,
      extractDomainFromHostname,
      generateSitePassword,
      normalizeDomain,
      toStoredSettings
    }
  };
});
