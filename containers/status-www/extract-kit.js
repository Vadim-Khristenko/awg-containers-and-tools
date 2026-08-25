/**
 * Extracts the Architect kit into the status page's stylesheet.
 *
 * Run from the repo root of awg-containers-and-tools:
 *   node containers/status-www/extract-kit.js
 *
 * The kit lives in the Architect repository, one directory over on this
 * machine; the extraction is a build-time copy, not a runtime dependency —
 * the status page must render with the uplink cut, so its stylesheet ships
 * inside the image. Re-run this after the kit changes.
 */
const fs = require("fs");
const path = require("path");

const here = __dirname;
const candidates = [
    path.resolve(here, "../../../../amneziawg-architect/assets/kit"),
    path.resolve(here, "../../../../gh-pages-vadim-kh/amneziawg-architect/assets/kit"),
];
const kitDir = candidates.find((p) => fs.existsSync(path.join(p, "tokens.css")));
if (!kitDir) {
    console.error("kit not found; looked in:\n  " + candidates.join("\n  "));
    process.exit(1);
}

const read = (f) => fs.readFileSync(path.join(kitDir, f), "utf8");
const tokens = read("tokens.css");
const buttons = read("buttons.css");
const surfaces = read("surfaces.css");

const cut = (src, start, end) => {
    const a = src.indexOf(start);
    const b = src.indexOf(end, a);
    if (a < 0 || b < 0) throw new Error("marker not found: " + start + " / " + end);
    return src.slice(a, b);
};

const btnFocus = cut(buttons, ".btn:focus-visible {", "/* Primary");
const btnBase = cut(buttons, ".btn {", "/* Primary");
// The secondary variant starts at its class: there is no section comment
// above it, the primary's comment is the only one in the file.
const btnPrimary = cut(buttons, "/* Primary", ".btn--secondary");
const card = cut(surfaces, ".card {", "a.card:hover");

const header = `/*
 * The Architect kit, extracted for a page that lives outside the app.
 *
 * This is the real theme: tokens.css verbatim, plus the two components this
 * page uses (the primary button and the card) from buttons.css and
 * surfaces.css. Not an approximation: the accent channels, the light-dark
 * schemes and the ink tiers are the same ones the site renders, so the page
 * reads as the site's sibling rather than as a tribute.
 *
 * Served from the same host as the page itself. A status page whose whole
 * point is privacy does not fetch its stylesheet from anywhere else.
 * Regenerate with: node containers/status-www/extract-kit.js
 */

`;

const out = header + tokens + "\n\n/* ── Components, from the kit ── */\n\n" + btnFocus + "\n" + btnBase + "\n" + btnPrimary + "\n" + card;
fs.writeFileSync(path.join(here, "architect.css"), out);
console.log("architect.css:", out.length, "bytes, kit from", kitDir);
