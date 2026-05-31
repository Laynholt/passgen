const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const pg = require("../password-generator.user.js");
const scriptSource = fs.readFileSync(path.join(__dirname, "..", "password-generator.user.js"), "utf8");
const packageJson = require("../package.json");

test("generateSitePassword is deterministic and keeps the requested policy", async () => {
  const password = await pg.__test.generateSitePassword({
    master: "bool char int float double",
    site: "Example.COM",
    length: 24,
    version: 1,
    counter: 0,
    alphabet: pg.__test.alphabetByMode("sym"),
    enforcePolicy: true,
    iterations: 1000
  });

  const again = await pg.__test.generateSitePassword({
    master: "bool char int float double",
    site: "example.com",
    length: 24,
    version: 1,
    counter: 0,
    alphabet: pg.__test.alphabetByMode("sym"),
    enforcePolicy: true,
    iterations: 1000
  });

  assert.equal(password, again);
  assert.equal(password.length, 24);
  assert.match(password, /[a-z]/);
  assert.match(password, /[A-Z]/);
  assert.match(password, /[0-9]/);
  assert.match(password, /[_-]/);
});

test("default settings do not include a built-in master key", () => {
  assert.equal(pg.__test.DEFAULT_SETTINGS.master, "");
  assert.equal(pg.__test.DEFAULT_SETTINGS.dontRemember, false);
});

test("metadata declares GitHub release URLs for userscript manager updates", () => {
  const releaseAssetUrl = "https://github.com/Laynholt/passgen/releases/latest/download/password-generator.user.js";

  assert.match(scriptSource, /^\/\/ @version\s+1\.1\.0$/m);
  assert.equal(packageJson.version, "1.1.0");
  assert.match(scriptSource, new RegExp(`^// @updateURL\\s+${releaseAssetUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"));
  assert.match(scriptSource, new RegExp(`^// @downloadURL\\s+${releaseAssetUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"));
});

test("settings saved with dontRemember omit the master key", () => {
  const saved = pg.__test.toStoredSettings({
    master: "secret master",
    length: 32,
    version: 2,
    counter: 4,
    alphabetMode: "nosym",
    dontRemember: true
  });

  assert.equal(saved.master, "");
  assert.equal(saved.length, 32);
  assert.equal(saved.version, 2);
  assert.equal(saved.counter, 4);
  assert.equal(saved.alphabetMode, "nosym");
  assert.equal(saved.dontRemember, true);
});

test("quick length presets expose normal and short password lengths", () => {
  assert.deepEqual(pg.__test.QUICK_LENGTH_PRESETS, [
    { label: "24", value: 24 },
    { label: "16", value: 16 }
  ]);
});

test("floating button position helpers clamp saved positions to the viewport", () => {
  assert.deepEqual(
    pg.__test.defaultFabPosition({ width: 360, height: 640 }),
    { x: 284, y: 512 }
  );
  assert.deepEqual(
    pg.__test.clampFabPosition({ x: -40, y: 900 }, { width: 360, height: 640 }),
    { x: 8, y: 570 }
  );
  assert.deepEqual(
    pg.__test.clampFabPosition({ x: 140, y: 200 }, { width: 360, height: 640 }),
    { x: 140, y: 200 }
  );
});

test("extractDomain strips common prefixes and keeps editable host defaults stable", () => {
  assert.equal(pg.__test.extractDomain("https://www.accounts.example.com/login"), "example.com");
  assert.equal(pg.__test.extractDomain("https://mail.google.co.uk/a/example"), "google.co.uk");
  assert.equal(pg.__test.extractDomain("not a url"), "");
});

test("floating button icon is inline SVG without external assets", () => {
  assert.match(pg.__test.FAB_ICON_SVG, /<svg\b/);
  assert.match(pg.__test.FAB_ICON_SVG, /data-part="lock-body"/);
  assert.match(pg.__test.FAB_ICON_SVG, /data-part="shackle"/);
  assert.match(pg.__test.FAB_ICON_SVG, /data-part="keyhole"/);
  assert.doesNotMatch(pg.__test.FAB_ICON_SVG, /data-part="key"/);
  assert.doesNotMatch(pg.__test.FAB_ICON_SVG, /data-part="key-ring"/);
  assert.doesNotMatch(pg.__test.FAB_ICON_SVG, /<img\b|href=["']https?:|src=/);
});
