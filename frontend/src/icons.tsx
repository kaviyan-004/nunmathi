/* Small 16x16 icons in the spirit of ZAP's Fugue icon set. */
type P = { className?: string };
const S = (p: { children: React.ReactNode } & P) => (
  <svg viewBox="0 0 16 16" width="16" height="16" className={p.className ?? "ico"} aria-hidden="true">
    {p.children}
  </svg>
);

export const IcFolder = () => (
  <S>
    <path d="M1 3h5l1.5 1.5H15v9H1z" fill="#f2c94c" stroke="#b8902a" strokeWidth=".8" />
  </S>
);
export const IcCapture = () => (
  <S>
    <rect x="2" y="1.5" width="12" height="13" rx="1" fill="#fff" stroke="#6b7c93" />
    <path d="M4 5h8M4 7.5h8M4 10h5" stroke="#3874c8" strokeWidth="1.2" />
  </S>
);
export const IcTunnel = () => (
  <S>
    <circle cx="3" cy="8" r="2.2" fill="#1c4f8c" />
    <circle cx="13" cy="8" r="2.2" fill="#1c4f8c" />
    <path d="M5 6.5h6v3H5z" fill="#e8a317" stroke="#a0700c" strokeWidth=".6" />
  </S>
);
export const IcKey = () => (
  <S>
    <circle cx="5" cy="8" r="3" fill="none" stroke="#c28b00" strokeWidth="1.8" />
    <path d="M8 8h7M12.5 8v2.5M14.5 8v2" stroke="#c28b00" strokeWidth="1.6" />
  </S>
);
export const IcLock = () => (
  <S>
    <rect x="3" y="7" width="10" height="7.5" rx="1" fill="#3d9b35" />
    <path d="M5 7V5a3 3 0 0 1 6 0v2" fill="none" stroke="#3d9b35" strokeWidth="1.6" />
  </S>
);
export const IcWarn = () => (
  <S>
    <path d="M8 1.5 15 14H1z" fill="#f0c419" stroke="#a37f00" strokeWidth=".8" />
    <path d="M8 6v4" stroke="#333" strokeWidth="1.6" />
    <circle cx="8" cy="12" r=".9" fill="#333" />
  </S>
);
export const IcOpen = () => (
  <S className="">
    <path d="M1 3h5l1.5 1.5H14V6H4L1.5 13z" fill="#f2c94c" stroke="#b8902a" strokeWidth=".8" />
    <path d="M4 6h11.5l-2.5 7.5H1.5z" fill="#f7dc80" stroke="#b8902a" strokeWidth=".8" />
  </S>
);
export const IcPlay = () => (
  <S className="">
    <path d="M4 2.5v11l9.5-5.5z" fill="#3d9b35" stroke="#256b1f" strokeWidth=".8" />
  </S>
);
export const IcReport = () => (
  <S className="">
    <rect x="2.5" y="1.5" width="11" height="13" fill="#fff" stroke="#6b7c93" />
    <rect x="4.5" y="9" width="1.8" height="3.5" fill="#e0301e" />
    <rect x="7.2" y="6.5" width="1.8" height="6" fill="#f08c00" />
    <rect x="9.9" y="4" width="1.8" height="8.5" fill="#3b82c4" />
  </S>
);
export const IcTrash = () => (
  <S className="">
    <path d="M3 4.5h10l-1 10H4z" fill="#d9dde3" stroke="#6b7280" strokeWidth=".8" />
    <path d="M2 3.5h12M6 2h4" stroke="#6b7280" strokeWidth="1.2" />
  </S>
);
export const IcRefresh = () => (
  <S className="">
    <path d="M13 8a5 5 0 1 1-1.6-3.7" fill="none" stroke="#1f6fb2" strokeWidth="1.8" />
    <path d="M13.5 1.8v3.8H9.7z" fill="#1f6fb2" />
  </S>
);
export const IcHelp = () => (
  <S className="">
    <circle cx="8" cy="8" r="6.5" fill="#3b82c4" />
    <path d="M6 6.2a2 2 0 1 1 2.6 1.9c-.5.2-.6.6-.6 1.2" fill="none" stroke="#fff" strokeWidth="1.5" />
    <circle cx="8" cy="11.7" r=".9" fill="#fff" />
  </S>
);
export const IcBolt = () => (
  <S className="">
    <path d="M9.5 1 3 9h4l-1 6 7-8.5H9z" fill="#f0c419" stroke="#a37f00" strokeWidth=".7" />
  </S>
);
export const IcHistory = () => (
  <S className="">
    <circle cx="8" cy="8" r="6.3" fill="#fff" stroke="#555" />
    <path d="M8 4v4.3l3 1.7" fill="none" stroke="#555" strokeWidth="1.3" />
  </S>
);
export const IcTerminal = () => (
  <S className="">
    <rect x="1" y="2" width="14" height="12" rx="1" fill="#2b2b2b" />
    <path d="M3.5 5.5 6 8l-2.5 2.5M7.5 11h4" stroke="#9ee37d" strokeWidth="1.3" fill="none" />
  </S>
);
export const IcRules = () => (
  <S className="">
    <rect x="2" y="1.5" width="12" height="13" fill="#fff" stroke="#6b7c93" />
    <path d="M4 4.5h1.5M4 8h1.5M4 11.5h1.5M7 4.5h5M7 8h5M7 11.5h5" stroke="#555" strokeWidth="1.1" />
  </S>
);
export const IcBrain = () => (
  <S className="">
    <circle cx="8" cy="8" r="6.3" fill="#e9e2f7" stroke="#7b3fb5" />
    <circle cx="5.5" cy="6" r="1.2" fill="#7b3fb5" />
    <circle cx="10.5" cy="6.5" r="1.2" fill="#7b3fb5" />
    <circle cx="8" cy="10.5" r="1.2" fill="#7b3fb5" />
    <path d="M5.5 6 10.5 6.5 8 10.5z" fill="none" stroke="#7b3fb5" strokeWidth=".8" />
  </S>
);
export const IcHome = () => (
  <S className="">
    <path d="M2 8 8 2.5 14 8" fill="none" stroke="#1c4f8c" strokeWidth="1.6" />
    <path d="M3.8 7.5V14h8.4V7.5" fill="#dbe8f7" stroke="#1c4f8c" />
  </S>
);
export const IcChart = () => (
  <S className="">
    <path d="M1.5 14.5h13" stroke="#555" />
    <path d="M2 12 5.5 7l3 3L14 3" fill="none" stroke="#1f6fb2" strokeWidth="1.6" />
  </S>
);
export const IcHex = () => (
  <S className="">
    <rect x="1" y="2" width="14" height="12" rx="1" fill="#fff" stroke="#6b7c93" />
    <text x="8" y="11" fontSize="6.5" textAnchor="middle" fontFamily="monospace" fill="#1f6fb2">0x</text>
  </S>
);
export const IcSliders = () => (
  <S className="">
    <path d="M2 4h12M2 8h12M2 12h12" stroke="#777" />
    <rect x="4" y="2.3" width="2.4" height="3.4" fill="#3874c8" />
    <rect x="9.5" y="6.3" width="2.4" height="3.4" fill="#3874c8" />
    <rect x="6" y="10.3" width="2.4" height="3.4" fill="#3874c8" />
  </S>
);
export const IcLive = () => (
  <S className="">
    <circle cx="8" cy="8" r="2.4" fill="#d9331f" />
    <path d="M4.6 4.6a4.8 4.8 0 0 0 0 6.8M11.4 4.6a4.8 4.8 0 0 1 0 6.8" fill="none" stroke="#d9331f" strokeWidth="1.4" />
    <path d="M2.4 2.4a8 8 0 0 0 0 11.2M13.6 2.4a8 8 0 0 1 0 11.2" fill="none" stroke="#d9331f" strokeWidth="1.2" opacity=".6" />
  </S>
);
export const IcStop = () => (
  <S className="">
    <rect x="3" y="3" width="10" height="10" rx="1" fill="#d9331f" stroke="#8f1d10" strokeWidth=".8" />
  </S>
);
