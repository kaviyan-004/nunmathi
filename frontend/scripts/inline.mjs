// Turns the Vite build in dist-app/ into one self-contained index.html for the desktop application.
// The page is loaded from disk (file://), where browsers refuse external module scripts, so every script,
// stylesheet and the favicon are inlined. No network access and no web server are needed at runtime.
import { readFileSync, writeFileSync, rmSync, readdirSync, copyFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const out = new URL("../dist-app/", import.meta.url).pathname;
let html = readFileSync(join(out, "index.html"), "utf8");

html = html.replace(/<script type="module" crossorigin src="\.\/([^"]+)"><\/script>/g, (_, f) => {
  const js = readFileSync(join(out, f), "utf8").replace(/<\/script/gi, "<\\/script");
  return `<script type="module">${js}</script>`;
});
html = html.replace(/<link rel="modulepreload"[^>]*>/g, "");
html = html.replace(/<link rel="stylesheet" crossorigin href="\.\/([^"]+)">/g, (_, f) => `<style>${readFileSync(join(out, f), "utf8")}</style>`);
html = html.replace(/<link rel="icon"[^>]*href="\.\/([^"]+\.svg)"[^>]*>/g, (_, f) => {
  const svg = readFileSync(join(out, f)).toString("base64");
  return `<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,${svg}">`;
});

if (/src="\.\/assets|href="\.\/assets/.test(html)) throw new Error("un-inlined asset left in index.html");
writeFileSync(join(out, "index.html"), html);
if (existsSync(join(out, "assets"))) rmSync(join(out, "assets"), { recursive: true });
for (const f of readdirSync(out)) if (f !== "index.html" && f !== "nunmathi.svg") rmSync(join(out, f), { recursive: true });

const png = new URL("../../packaging/nunmathi-256.png", import.meta.url).pathname;
if (existsSync(png)) copyFileSync(png, join(out, "nunmathi.png"));
console.log(`dist-app/index.html: ${(html.length / 1024).toFixed(0)} KiB, self-contained`);
