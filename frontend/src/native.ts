/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Transport between the UI and the Nunmathi engine.
 *
 * In the desktop application the page is loaded from disk inside a native window and there is no HTTP server:
 * every API call goes through the pywebview bridge (window.pywebview.api), which runs the engine in-process.
 * In development (vite dev server / `nunmathi serve`) the same calls fall back to fetch().
 */

type Packed = { status: number; headers: Record<string, string>; text?: string; b64?: string };

interface NativeApi {
  request(method: string, path: string, body?: string | null, bodyB64?: string | null, contentType?: string | null): Promise<Packed>;
  open_capture(): Promise<Packed | null>;
  analyze_path(path: string): Promise<Packed>;
  open_text(): Promise<{ name: string; text: string } | null>;
  save_download(path: string, suggested: string, openAfter?: boolean): Promise<{ ok: boolean; path?: string; error?: string; cancelled?: boolean }>;
  show_html(path: string, title: string): Promise<{ ok: boolean; error?: string }>;
  open_url(url: string): Promise<boolean>;
  app_info(): Promise<{ engine: string; data_dir: string; platform: string }>;
}

const w = window as any;

/** True inside the desktop application (the page was loaded from disk, not served over HTTP). */
export const isNative = location.protocol === "file:" || location.protocol === "about:" || !!w.pywebview;

let readyP: Promise<NativeApi> | null = null;
/** Resolves once pywebview has injected its bridge (it arrives shortly after the page loads). */
export function native(): Promise<NativeApi> {
  if (!readyP) {
    readyP = new Promise((resolve) => {
      const done = () => resolve(w.pywebview.api as NativeApi);
      if (w.pywebview?.api?.request) done();
      else window.addEventListener("pywebviewready", done, { once: true });
    });
  }
  return readyP;
}

function toResponse(p: Packed): Response {
  let body: BodyInit | null = null;
  if (p.b64 != null) {
    const bin = atob(p.b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    body = u8;
  } else if (p.text) body = p.text;
  const nullBody = p.status === 204 || p.status === 304;
  return new Response(nullBody ? null : body, { status: p.status, headers: p.headers });
}

function b64(buf: ArrayBuffer): string {
  const u8 = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s);
}

/** fetch() replacement used by api.ts. */
export async function http(path: string, init: RequestInit = {}): Promise<Response> {
  if (!isNative) return fetch(path, init);
  const n = await native();
  const method = (init.method ?? "GET").toUpperCase();
  const hdrs = new Headers(init.headers);
  const ctype = hdrs.get("Content-Type");
  let text: string | null = null;
  let bin: string | null = null;
  const b = init.body;
  if (typeof b === "string") text = b;
  else if (b instanceof Blob) bin = b64(await b.arrayBuffer());
  else if (b instanceof ArrayBuffer) bin = b64(b);
  const p = await n.request(method, path, text, bin, ctype);
  return toResponse(p);
}

/** Upload a capture the user picked or dropped. Dropped files carry their real path in the desktop app. */
export async function nativeUpload(file: File): Promise<Response> {
  const n = await native();
  const full = (file as any).pywebviewFullPath as string | undefined;
  if (full) return toResponse(await n.analyze_path(full));
  return http(`/api/analyses?filename=${encodeURIComponent(file.name)}`, {
    method: "POST",
    body: file,
    headers: { "Content-Type": "application/octet-stream" },
  });
}

/** Native "Open capture" dialog; resolves to the created analysis response, or null when cancelled. */
export async function nativeOpenCapture(): Promise<Response | null> {
  const n = await native();
  const p = await n.open_capture();
  return p ? toResponse(p) : null;
}

export async function nativeOpenText(): Promise<{ name: string; text: string } | null> {
  return (await native()).open_text();
}

/** Save an API document (PDF/JSON/YAML) through a native Save dialog and open it with the system viewer. */
export async function nativeSave(path: string, suggested: string, openAfter = true) {
  return (await native()).save_download(path, suggested, openAfter);
}

export async function nativeShowHtml(path: string, title: string) {
  return (await native()).show_html(path, title);
}

/**
 * In the desktop app, links to external references (RFCs, NIST, MITRE ATT&CK) open in the user's browser
 * instead of navigating the application window away from the UI.
 */
export function installLinkHandler(): void {
  if (!isNative) return;
  document.addEventListener(
    "click",
    (e) => {
      const a = (e.target as HTMLElement | null)?.closest?.("a") as HTMLAnchorElement | null;
      if (!a) return;
      const href = a.getAttribute("href") ?? "";
      if (/^https?:\/\//i.test(href)) {
        e.preventDefault();
        native().then((n) => n.open_url(href));
      }
    },
    true,
  );
}
