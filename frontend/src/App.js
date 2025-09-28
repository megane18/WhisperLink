// import React, { useEffect, useMemo, useState } from "react";
// import QRCode from "qrcode";
// import './index.css'

// /* ====== Config ====== */
// const API_BASE =
//   (typeof process !== "undefined" &&
//     process.env &&
//     process.env.REACT_APP_API_BASE) ||
//   "http://localhost:8080";
// const ALLOW_PLAINTEXT =
//   typeof process !== "undefined" &&
//   process.env &&
//   process.env.REACT_APP_ALLOW_PLAINTEXT === "true";

// /* ====== Crypto helpers ====== */
// const enc = new TextEncoder();
// const b64u = {
//   enc: (buf) => {
//     const b = Array.from(new Uint8Array(buf))
//       .map((x) => String.fromCharCode(x))
//       .join("");
//     return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
//   },
// };
// async function randomKey() {
//   const k = await crypto.subtle.generateKey(
//     { name: "AES-GCM", length: 256 },
//     true,
//     ["encrypt", "decrypt"]
//   );
//   const raw = await crypto.subtle.exportKey("raw", k);
//   return { key: k, raw };
// }
// async function deriveKeyPBKDF2(password, saltBytes, iterations = 100000) {
//   const base = await crypto.subtle.importKey(
//     "raw",
//     enc.encode(password),
//     "PBKDF2",
//     false,
//     ["deriveKey"]
//   );
//   return crypto.subtle.deriveKey(
//     { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
//     base,
//     { name: "AES-GCM", length: 256 },
//     false,
//     ["encrypt", "decrypt"]
//   );
// }
// async function encryptBytes(key, bytes) {
//   const iv = crypto.getRandomValues(new Uint8Array(12));
//   const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
//   return { iv, ct };
// }

// /* ====== Presets ====== */
// const presets = [
//   { label: "5 min", seconds: 5 * 60 },
//   { label: "30 min", seconds: 30 * 60 },
//   { label: "45 min", seconds: 45 * 60 },
//   { label: "1 hour", seconds: 60 * 60 },
//   { label: "1 day", seconds: 24 * 60 * 60 },
//   { label: "1 week", seconds: 7 * 24 * 60 * 60 },
//   { label: "Custom…", seconds: -1 },
// ];

// /* ====== Modal ====== */
// function Modal({ open, title, children, onClose, actions }) {
//   if (!open) return null;
//   return (
//     <div className="modal-backdrop" onClick={onClose}>
//       <div className="modal" onClick={(e) => e.stopPropagation()}>
//         {title && <div className="modal-header">{title}</div>}
//         <div className="modal-body">{children}</div>
//         <div className="modal-actions">
//           {actions?.length ? actions : <button className="btn" onClick={onClose}>Close</button>}
//         </div>
//       </div>
//     </div>
//   );
// }

// export default function App() {
//   return <WhisperLink />;
// }

// function WhisperLink() {
//   /* Dark mode default */
//   const [theme, setTheme] = useState("dark");
//   useEffect(() => { document.documentElement.dataset.theme = theme; }, [theme]);

//   // content
//   const [text, setText] = useState("");
//   const [chars, setChars] = useState(0);
//   const [file, setFile] = useState(null);
//   const [fileInputKey, setFileInputKey] = useState(0);

//   // options
//   const [preset, setPreset] = useState(presets[0].label);
//   const [customTTL, setCustomTTL] = useState(3600);
//   const [burn, setBurn] = useState(false);
//   const [maxReads, setMaxReads] = useState(1);
//   const [passwordMode, setPasswordMode] = useState(false);
//   const [password, setPassword] = useState("");
//   const [encryptEnabled, setEncryptEnabled] = useState(true);

//   // Slack
//   const [teams, setTeams] = useState([]);
//   const [teamId, setTeamId] = useState("");
//   const [emails, setEmails] = useState("");

//   // result
//   const [link, setLink] = useState("");
//   const [qrDataURL, setQRDataURL] = useState("");
//   const [busy, setBusy] = useState(false);
//   const [error, setError] = useState("");

//   // modal
//   const [modal, setModal] = useState({ open: false, title: "", body: null, actions: null });

//   useEffect(() => setChars(text.length), [text]);

//   // load teams
//   const loadTeams = async () => {
//     try {
//       const r = await fetch(`${API_BASE}/slack/teams`);
//       if (r.ok) {
//         const j = await r.json();
//         setTeams(j || []);
//         if ((j || []).length && !teamId) setTeamId(j[0].teamId);
//       }
//     } catch {}
//   };
//   useEffect(() => {
//     loadTeams();
//     const onFocus = () => loadTeams();
//     window.addEventListener("focus", onFocus);
//     return () => window.removeEventListener("focus", onFocus);
//   }, []);

//   const ttlSeconds = useMemo(() => {
//     const p = presets.find((x) => x.label === preset);
//     if (!p) return 3600;
//     if (p.seconds === -1) return Number(customTTL) || 0;
//     return p.seconds;
//   }, [preset, customTTL]);

//   const canCreate = useMemo(() => file || text.trim().length > 0, [file, text]);
//   const canSendSlack = useMemo(
//     () => !!teamId && emails.trim().length > 0 && (link || canCreate),
//     [teamId, emails, link, canCreate]
//   );

//   const onFile = (e) => {
//     const f = e.target.files?.[0];
//     if (!f) return setFile(null);
//     if (f.size > 1 << 20) {
//       setModal({ open: true, title: "File too large", body: "Max file size is 1 MB." });
//       e.target.value = "";
//       setFile(null);
//       return;
//     }
//     setFile(f);
//   };

//   const clearAll = () => {
//     setText("");
//     setFile(null);
//     setFileInputKey((k) => k + 1);
//     setPreset(presets[0].label);
//     setCustomTTL(3600);
//     setBurn(false);
//     setMaxReads(1);
//     setPasswordMode(false);
//     setPassword("");
//     setEncryptEnabled(true);
//     setTeamId(teams[0]?.teamId || "");
//     setEmails("");
//     setLink("");
//     setQRDataURL("");
//     setBusy(false);
//     setError("");
//     setModal({ open: true, title: "Cleared", body: "All inputs have been reset." });
//   };

//   const createPaste = async () => {
//     setError(""); setLink(""); setQRDataURL(""); setBusy(true);
//     try {
//       // bytes
//       let bytes, meta = null;
//       if (file) {
//         bytes = await file.arrayBuffer();
//         meta = { filename: file.name, mime: file.type || "application/octet-stream" };
//       } else {
//         bytes = new TextEncoder().encode(text);
//       }

//       // plaintext path (if allowed and chosen)
//       if (!encryptEnabled) {
//         if (!ALLOW_PLAINTEXT) {
//           setBusy(false);
//           setModal({
//             open: true,
//             title: "Plaintext disabled",
//             body: "Your backend is zero-knowledge (ciphertext-only). Enable plaintext on backend and set REACT_APP_ALLOW_PLAINTEXT=true if you want raw storage.",
//           });
//           return;
//         }
//         const body = {
//           ciphertext: b64u.enc(bytes),
//           nonce: "",
//           alg: "PLAINTEXT",
//           ttlSeconds,
//           burnAfterRead: burn,
//           maxReads: Number(maxReads),
//           meta,
//         };
//         const res = await fetch(`${API_BASE}/api/paste`, {
//           method: "POST", headers: { "Content-Type":"application/json" }, body: JSON.stringify(body),
//         });
//         const j = await res.json().catch(()=>({}));
//         if (!res.ok) throw new Error(j.error || `HTTP ${res.status}`);
//         setLink(j.url);
//         try { setQRDataURL(await QRCode.toDataURL(j.url, { margin:1, scale:4 })); } catch {}
//         setModal({ open: true, title: "Link ready", body: "Plaintext link has been created." });
//         return;
//       }

//       // encrypt path
//       let keyObj, keyRaw, saltBytes, kdf = null;
//       if (passwordMode) {
//         saltBytes = crypto.getRandomValues(new Uint8Array(16));
//         keyObj = await deriveKeyPBKDF2(password, saltBytes, 100000);
//         kdf = { name: "PBKDF2", iterations: 100000, digest: "SHA-256" };
//       } else {
//         const { key, raw } = await randomKey();
//         keyObj = key; keyRaw = raw;
//       }

//       const { iv, ct } = await encryptBytes(keyObj, bytes);
//       const body = {
//         ciphertext: b64u.enc(ct),
//         nonce: b64u.enc(iv),
//         alg: "AES-256-GCM",
//         ttlSeconds,
//         burnAfterRead: burn,
//         maxReads: Number(maxReads),
//         meta,
//       };
//       if (passwordMode) {
//         body.salt = b64u.enc(saltBytes.buffer);
//         body.kdf = kdf;
//       }

//       const res = await fetch(`${API_BASE}/api/paste`, {
//         method: "POST", headers: { "Content-Type":"application/json" },
//         body: JSON.stringify(body),
//       });
//       const j = await res.json().catch(()=>({}));
//       if (!res.ok) throw new Error(j.error || `HTTP ${res.status}`);

//       let url = j.url;
//       if (!passwordMode && keyRaw) url = `${url}#${b64u.enc(keyRaw)}`;
//       setLink(url);
//       try { setQRDataURL(await QRCode.toDataURL(url, { margin:1, scale:4 })); } catch {}
//       setModal({ open: true, title: "Link ready", body: "Your secure link has been created." });
//     } catch(e) {
//       setError(e.message || String(e));
//       setModal({ open: true, title: "Error", body: String(e.message || e) });
//     } finally { setBusy(false); }
//   };

//   const copyLink = async () => {
//     if (!link) return;
//     try {
//       await navigator.clipboard.writeText(link);
//       setModal({ open:true, title:"Copied", body:"Link copied to clipboard." });
//     } catch {
//       setModal({ open:true, title:"Copy failed", body:"Select the link and copy manually." });
//     }
//   };

//   const sendSlack = async () => {
//     if (!link) await createPaste();
//     if (!link) return;
//     try {
//       const recipients = emails.split(",").map(s=>s.trim()).filter(Boolean);
//       const r = await fetch(`${API_BASE}/dev/slack/share`, {
//         method:"POST", headers:{ "Content-Type":"application/json" },
//         body: JSON.stringify({ teamId, link, recipients }),
//       });
//       const j = await r.json();
//       setModal({
//         open:true,
//         title:"Slack result",
//         body: (
//           <div>
//             <div style={{marginBottom:8}}><strong>URL:</strong> <span style={{wordBreak:"break-all"}}>{j.url}</span></div>
//             <div><strong>Sent to:</strong> {j.sent?.length ? j.sent.join(", ") : "none"}</div>
//             {j.failed?.length ? <div style={{marginTop:6}}><strong>Failed:</strong> {JSON.stringify(j.failed)}</div> : null}
//           </div>
//         )
//       });
//     } catch(e){
//       setModal({ open:true, title:"Slack send failed", body:String(e.message || e) });
//     }
//   };

//   return (
//     <>
//       <Modal
//         open={modal.open}
//         title={modal.title}
//         onClose={()=>setModal({ open:false, title:"", body:null, actions:null })}
//         actions={modal.actions}
//       >
//         {modal.body}
//       </Modal>

//       <div className="wrap">
//         {/* Header */}
//         <div className="header">
//           <div className="brand">
//             <h1 className="title">WhisperLink</h1>
//             <p className="subtitle">Share secrets with zero-knowledge encryption.</p>
//           </div>
//           <div className="toolbar">
//             <button className="btn" onClick={()=>setTheme(theme==="light"?"dark":"light")}>
//               {theme==="light" ? "Dark mode" : "Light mode"}
//             </button>
//             <button className="btn" onClick={()=>window.open(`${API_BASE}/slack/install`,"_blank")}>
//               Add to Slack
//             </button>
//             <button className="btn" onClick={loadTeams}>Refresh</button>
//             <button className="btn danger" onClick={clearAll}>Clear</button>
//           </div>
//         </div>

//         {/* Composer */}
//         <section className="card">
//           <div className="filepicker">
//             <input key={fileInputKey} id="file" type="file" onChange={onFile} />
//             <label htmlFor="file" className="pick-btn">Choose file</label>
//             <span className="filename">{file ? `${file.name} (${(file.size/1024).toFixed(1)} KB)` : "No file selected"}</span>
//             <span className="hint">Max 1 MB</span>
//           </div>

//           {!file && (
//             <>
//               <textarea
//                 value={text}
//                 onChange={(e)=>setText(e.target.value)}
//                 placeholder="Paste tokens, env vars, or a short note…"
//               />
//               <div className="hint right">{chars} chars</div>
//             </>
//           )}

//           <hr />

//           <div className="grid2">
//             <label>
//               Encrypt
//               <select
//                 value={encryptEnabled ? "on" : "off"}
//                 onChange={(e)=>setEncryptEnabled(e.target.value === "on")}
//                 style={{marginTop:6}}
//                 disabled={!ALLOW_PLAINTEXT && !encryptEnabled}
//               >
//                 <option value="on">On (recommended)</option>
//                 <option value="off">Off (plaintext)</option>
//               </select>
//               {!ALLOW_PLAINTEXT && <div className="hint">Plaintext disabled by config.</div>}
//             </label>

//             <label>
//               Expiration
//               <select value={preset} onChange={(e)=>setPreset(e.target.value)} style={{marginTop:6}}>
//                 {presets.map(p=> <option key={p.label} value={p.label}>{p.label}</option>)}
//               </select>
//             </label>

//             {preset==="Custom…" && (
//               <label>
//                 Custom TTL (seconds)
//                 <input type="number" min={0} value={customTTL} onChange={(e)=>setCustomTTL(e.target.value)} style={{marginTop:6}} />
//               </label>
//             )}

//             <label className="row">
//               <input type="checkbox" checked={burn} onChange={(e)=>setBurn(e.target.checked)} />
//               Burn after first read
//             </label>

//             <label>
//               Max reads
//               <input type="number" min={1} value={maxReads} onChange={(e)=>setMaxReads(e.target.value)} style={{marginTop:6}}/>
//             </label>

//             <label className="row">
//               <input
//                 type="checkbox"
//                 checked={passwordMode}
//                 onChange={(e)=>setPasswordMode(e.target.checked)}
//                 disabled={!encryptEnabled}
//               />
//               Password protect (no key in URL)
//             </label>

//             {passwordMode && encryptEnabled && (
//               <label>
//                 Password
//                 <input type="password" value={password} onChange={(e)=>setPassword(e.target.value)} style={{marginTop:6}}/>
//               </label>
//             )}
//           </div>

//           <div className="row" style={{marginTop:10}}>
//             <button className="btn primary" onClick={createPaste} disabled={!canCreate || busy}>
//               {busy ? "Working…" : "Create link"}
//             </button>
//             {link && <button className="btn" onClick={copyLink}>Copy link</button>}
//           </div>

//           {error && <div className="error">Error: {error}</div>}

//           {link && (
//             <div className="section">
//               <div className="linkRow">
//                 <div className="codeblock">{link}</div>
//                 <a className="btn link" href={link} target="_blank" rel="noreferrer">Open</a>
//               </div>
//               {qrDataURL && <div style={{marginTop:8}}>
//                 <img className="qr" src={qrDataURL} alt="QR" />
//               </div>}
//             </div>
//           )}
//         </section>

//         {/* Slack */}
//         <section className="card section">
//           <div className="grid2">
//             <label>
//               Workspace
//               <select value={teamId} onChange={(e)=>setTeamId(e.target.value)} style={{marginTop:6}}>
//                 {!teams.length && <option>No installs yet</option>}
//                 {teams.map(t=> <option key={t.teamId} value={t.teamId}>{t.teamName} ({t.teamId})</option>)}
//               </select>
//             </label>
//             <label>
//               Recipient emails (comma-separated)
//               <input type="text" value={emails} onChange={(e)=>setEmails(e.target.value)} placeholder="alice@acme.com, bob@acme.com" style={{marginTop:6}}/>
//             </label>
//           </div>

//           {!!teams.length && (
//             <div className="workspace-list">
//               {teams.map(t => (
//                 <span key={t.teamId} className="workspace-pill">
//                   <span>Installed</span>
//                   <strong>{t.teamName}</strong>
//                 </span>
//               ))}
//             </div>
//           )}

//           <div className="slack-actions" style={{marginTop:10}}>
//             <button
//               className="btn"
//               onClick={async()=>{ if(!link) await createPaste(); if(link || text || file) sendSlack(); }}
//               disabled={!teamId || !emails.trim()}
//             >
//               Send link via Slack
//             </button>

//             <button className="btn ghost" onClick={()=>window.open(`${API_BASE}/slack/install`, "_blank")}>
//               Install another workspace
//             </button>

//             <button className="btn ghost" onClick={loadTeams}>
//               Refresh workspaces
//             </button>
//           </div>
//         </section>
//       </div>
//     </>
//   );
// }


import React, { useEffect, useMemo, useState } from "react";
import QRCode from "qrcode";
import './index.css'

/* ====== Config ====== */
const API_BASE =
  (typeof process !== "undefined" &&
    process.env &&
    process.env.REACT_APP_API_BASE) ||
  "http://localhost:8080";
const ALLOW_PLAINTEXT =
  typeof process !== "undefined" &&
  process.env &&
  process.env.REACT_APP_ALLOW_PLAINTEXT === "true";

/* Real Slack share endpoint (uses users.lookupByEmail + DM) */
const SLACK_SHARE_PATH = "/slack/share";

/* ====== Crypto helpers ====== */
const enc = new TextEncoder();
const b64u = {
  enc: (buf) => {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    const b = Array.from(u8).map((x) => String.fromCharCode(x)).join("");
    return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  },
};
async function randomKey() {
  const k = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  const raw = await crypto.subtle.exportKey("raw", k);
  return { key: k, raw };
}
async function deriveKeyPBKDF2(password, saltBytes, iterations = 100000) {
  const base = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function encryptBytes(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  return { iv, ct };
}

/* ====== Presets ====== */
const presets = [
  { label: "5 min", seconds: 5 * 60 },
  { label: "30 min", seconds: 30 * 60 },
  { label: "45 min", seconds: 45 * 60 },
  { label: "1 hour", seconds: 60 * 60 },
  { label: "1 day", seconds: 24 * 60 * 60 },
  { label: "1 week", seconds: 7 * 24 * 60 * 60 },
  { label: "Custom…", seconds: -1 },
];

/* ====== Modal ====== */
function Modal({ open, title, children, onClose, actions }) {
  if (!open) return null;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        {title && <div className="modal-header">{title}</div>}
        <div className="modal-body">{children}</div>
        <div className="modal-actions">
          {actions?.length ? actions : <button className="btn" onClick={onClose}>Close</button>}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return <WhisperLink />;
}

function WhisperLink() {
  /* Dark mode default */
  const [theme, setTheme] = useState("dark");
  useEffect(() => { document.documentElement.dataset.theme = theme; }, [theme]);

  // content
  const [text, setText] = useState("");
  const [chars, setChars] = useState(0);
  const [file, setFile] = useState(null);
  const [fileInputKey, setFileInputKey] = useState(0);

  // options
  const [preset, setPreset] = useState(presets[0].label);
  const [customTTL, setCustomTTL] = useState(3600);
  const [burn, setBurn] = useState(false);
  const [maxReads, setMaxReads] = useState(1);
  const [passwordMode, setPasswordMode] = useState(false);
  const [password, setPassword] = useState("");
  const [encryptEnabled, setEncryptEnabled] = useState(true);

  // Slack
  const [teams, setTeams] = useState([]);
  const [teamId, setTeamId] = useState("");
  const [emails, setEmails] = useState("");

  // result
  const [link, setLink] = useState("");
  const [qrDataURL, setQRDataURL] = useState("");
  const [busy, setBusy] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState("");

  // modal
  const [modal, setModal] = useState({ open: false, title: "", body: null, actions: null });

  useEffect(() => setChars(text.length), [text]);

  // load teams
  const loadTeams = async () => {
    try {
      const r = await fetch(`${API_BASE}/slack/teams`);
      if (r.ok) {
        const j = await r.json();
        setTeams(j || []);
        if ((j || []).length && !teamId) setTeamId(j[0].teamId);
      } else {
        // if server restarted and installs are gone, we’ll show the “no installs” hint below
        setTeams([]);
      }
    } catch {
      setTeams([]);
    }
  };
  useEffect(() => {
    loadTeams();
    const onFocus = () => loadTeams();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, []);

  const ttlSeconds = useMemo(() => {
    const p = presets.find((x) => x.label === preset);
    if (!p) return 3600;
    if (p.seconds === -1) return Number(customTTL) || 0;
    return p.seconds;
  }, [preset, customTTL]);

  const canCreate = useMemo(() => file || text.trim().length > 0, [file, text]);
  const canSendSlack = useMemo(
    () => !!teamId && emails.trim().length > 0 && (link || canCreate),
    [teamId, emails, link, canCreate]
  );

  const onFile = (e) => {
    const f = e.target.files?.[0];
    if (!f) return setFile(null);
    if (f.size > 1 << 20) {
      setModal({ open: true, title: "File too large", body: "Max file size is 1 MB." });
      e.target.value = "";
      setFile(null);
      return;
    }
    setFile(f);
  };

  const clearAll = () => {
    setText("");
    setFile(null);
    setFileInputKey((k) => k + 1);
    setPreset(presets[0].label);
    setCustomTTL(3600);
    setBurn(false);
    setMaxReads(1);
    setPasswordMode(false);
    setPassword("");
    setEncryptEnabled(true);
    setTeamId(teams[0]?.teamId || "");
    setEmails("");
    setLink("");
    setQRDataURL("");
    setBusy(false);
    setSending(false);
    setError("");
    setModal({ open: true, title: "Cleared", body: "All inputs have been reset." });
  };
  const createPaste = async () => {
    setError(""); setLink(""); setQRDataURL(""); setBusy(true);
    try {
      // bytes
      let bytes, meta = null;
      if (file) {
        bytes = await file.arrayBuffer();
        meta = { filename: file.name, mime: file.type || "application/octet-stream" };
      } else {
        bytes = new TextEncoder().encode(text);
      }

      // plaintext path (if allowed and chosen)
      if (!encryptEnabled) {
        if (!ALLOW_PLAINTEXT) {
          setBusy(false);
          setModal({
            open: true,
            title: "Plaintext disabled",
            body: "Your backend is zero-knowledge (ciphertext-only). Enable plaintext on backend and set REACT_APP_ALLOW_PLAINTEXT=true if you want raw storage.",
          });
          return;
        }
        const body = {
          ciphertext: b64u.enc(bytes),
          nonce: "",
          alg: "PLAINTEXT",
          ttlSeconds,
          burnAfterRead: burn,
          maxReads: Number(maxReads),
          meta,
        };
        const res = await fetch(`${API_BASE}/api/paste`, {
          method: "POST", headers: { "Content-Type":"application/json" }, body: JSON.stringify(body),
        });
        const j = await res.json().catch(()=>({}));
        if (!res.ok) throw new Error(j.error || `HTTP ${res.status}`);
        setLink(j.url);
        try { setQRDataURL(await QRCode.toDataURL(j.url, { margin:1, scale:4 })); } catch {}
        setModal({ open: true, title: "Link ready", body: "Plaintext link has been created." });
        return;
      }

      // encrypt path
      let keyObj, keyRaw, saltBytes, kdf = null;
      if (passwordMode) {
        saltBytes = crypto.getRandomValues(new Uint8Array(16));
        keyObj = await deriveKeyPBKDF2(password, saltBytes, 100000);
        kdf = { name: "PBKDF2", iterations: 100000, digest: "SHA-256" };
      } else {
        const { key, raw } = await randomKey();
        keyObj = key; keyRaw = raw;
      }

      const { iv, ct } = await encryptBytes(keyObj, bytes);
      const body = {
        ciphertext: b64u.enc(ct),
        nonce: b64u.enc(iv),
        alg: "AES-256-GCM",
        ttlSeconds,
        burnAfterRead: burn,
        maxReads: Number(maxReads),
        meta,
      };
      if (passwordMode) {
        body.salt = b64u.enc(saltBytes.buffer);
        body.kdf = kdf;
      }

      const res = await fetch(`${API_BASE}/api/paste`, {
        method: "POST", headers: { "Content-Type":"application/json" },
        body: JSON.stringify(body),
      });
      const j = await res.json().catch(()=>({}));
      if (!res.ok) throw new Error(j.error || `HTTP ${res.status}`);

      let url = j.url;
      if (!passwordMode && keyRaw) url = `${url}#${b64u.enc(keyRaw)}`;
      setLink(url);
      try { setQRDataURL(await QRCode.toDataURL(url, { margin:1, scale:4 })); } catch {}
      setModal({ open: true, title: "Link ready", body: "Your secure link has been created." });
    } catch(e) {
      setError(e.message || String(e));
      setModal({ open: true, title: "Error", body: String(e.message || e) });
    } finally { setBusy(false); }
  };

  const copyLink = async () => {
    if (!link) return;
    try {
      await navigator.clipboard.writeText(link);
      setModal({ open:true, title:"Copied", body:"Link copied to clipboard." });
    } catch {
      setModal({ open:true, title:"Copy failed", body:"Select the link and copy manually." });
    }
  };

  const parseEmails = (s) =>
    s.split(",")
      .map(v => v.trim())
      .filter(v => v.length);

  const sendSlack = async () => {
    if (!link) await createPaste();
    if (!link) return;
    setSending(true);
    try {
      const recipients = parseEmails(emails);
      const r = await fetch(`${API_BASE}${SLACK_SHARE_PATH}`, {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ teamId, link, recipients }),
      });
      const j = await r.json().catch(()=> ({}));

      if (!r.ok) {
        throw new Error(j.error || `Slack share failed (HTTP ${r.status})`);
      }

      const sent = Array.isArray(j.sent) ? j.sent : [];
      const failed = Array.isArray(j.failed) ? j.failed : [];
      setModal({
        open:true,
        title:"Slack result",
        body: (
          <div>
            <div style={{marginBottom:8}}>
              <strong>URL:</strong>{" "}
              <span style={{wordBreak:"break-all"}}>{j.url || link}</span>
            </div>
            <div><strong>Sent to:</strong> {sent.length ? sent.join(", ") : "none"}</div>
            {failed.length ? (
              <div style={{marginTop:6}}>
                <strong>Failed:</strong>
                <ul style={{marginTop:4}}>
                  {failed.map((f, i) => <li key={i} style={{wordBreak:"break-all"}}>{String(f)}</li>)}
                </ul>
                <div className="hint" style={{marginTop:6}}>
                  Tip: Ensure the email matches the Slack account in that workspace, the bot is installed for this team, and DMs are permitted by the org.
                </div>
              </div>
            ) : null}
          </div>
        )
      });
    } catch(e){
      setModal({ open:true, title:"Slack send failed", body:String(e.message || e) });
    } finally {
      setSending(false);
    }
  };

  return (
    <>
      <Modal
        open={modal.open}
        title={modal.title}
        onClose={()=>setModal({ open:false, title:"", body:null, actions:null })}
        actions={modal.actions}
      >
        {modal.body}
      </Modal>

      <div className="wrap">
        {/* Header */}
        <div className="header">
          <div className="brand">
            <h1 className="title">WhisperLink</h1>
            <p className="subtitle">Share secrets with zero-knowledge encryption.</p>
          </div>
          <div className="toolbar">
            <button className="btn" onClick={()=>setTheme(theme==="light"?"dark":"light")}>
              {theme==="light" ? "Dark mode" : "Light mode"}
            </button>
            <button className="btn" onClick={()=>window.open(`${API_BASE}/slack/install`,"_blank")}>
              Add to Slack
            </button>
            <button className="btn" onClick={loadTeams}>Refresh</button>
            <button className="btn danger" onClick={clearAll}>Clear</button>
          </div>
        </div>

        {/* Composer */}
        <section className="card">
          <div className="filepicker">
            <input key={fileInputKey} id="file" type="file" onChange={onFile} />
            <label htmlFor="file" className="pick-btn">Choose file</label>
            <span className="filename">{file ? `${file.name} (${(file.size/1024).toFixed(1)} KB)` : "No file selected"}</span>
            <span className="hint">Max 1 MB</span>
          </div>

          {!file && (
            <>
              <textarea
                value={text}
                onChange={(e)=>setText(e.target.value)}
                placeholder="Paste tokens, env vars, or a short note…"
              />
              <div className="hint right">{chars} chars</div>
            </>
          )}

          <hr />

          <div className="grid2">
            <label>
              Encrypt
              <select
                value={encryptEnabled ? "on" : "off"}
                onChange={(e)=>setEncryptEnabled(e.target.value === "on")}
                style={{marginTop:6}}
                disabled={!ALLOW_PLAINTEXT && !encryptEnabled}
              >
                <option value="on">On (recommended)</option>
                <option value="off">Off (plaintext)</option>
              </select>
              {!ALLOW_PLAINTEXT && <div className="hint">Plaintext disabled by config.</div>}
            </label>

            <label>
              Expiration
              <select value={preset} onChange={(e)=>setPreset(e.target.value)} style={{marginTop:6}}>
                {presets.map(p=> <option key={p.label} value={p.label}>{p.label}</option>)}
              </select>
            </label>

            {preset==="Custom…" && (
              <label>
                Custom TTL (seconds)
                <input type="number" min={0} value={customTTL} onChange={(e)=>setCustomTTL(e.target.value)} style={{marginTop:6}} />
              </label>
            )}

            <label className="row">
              <input type="checkbox" checked={burn} onChange={(e)=>setBurn(e.target.checked)} />
              Burn after first read
            </label>

            <label>
              Max reads
              <input type="number" min={1} value={maxReads} onChange={(e)=>setMaxReads(e.target.value)} style={{marginTop:6}}/>
            </label>

            <label className="row">
              <input
                type="checkbox"
                checked={passwordMode}
                onChange={(e)=>setPasswordMode(e.target.checked)}
                disabled={!encryptEnabled}
              />
              Password protect (no key in URL)
            </label>

            {passwordMode && encryptEnabled && (
              <label>
                Password
                <input type="password" value={password} onChange={(e)=>setPassword(e.target.value)} style={{marginTop:6}}/>
              </label>
            )}
          </div>

          <div className="row" style={{marginTop:10}}>
            <button className="btn primary" onClick={createPaste} disabled={!canCreate || busy}>
              {busy ? "Working…" : "Create link"}
            </button>
            {link && <button className="btn" onClick={copyLink}>Copy link</button>}
          </div>

          {error && <div className="error">Error: {error}</div>}

          {link && (
            <div className="section">
              <div className="linkRow">
                <div className="codeblock">{link}</div>
                <a className="btn link" href={link} target="_blank" rel="noreferrer">Open</a>
              </div>
              {qrDataURL && <div style={{marginTop:8}}>
                <img className="qr" src={qrDataURL} alt="QR" />
              </div>}
            </div>
          )}
        </section>

        {/* Slack */}
        <section className="card section">
          <div className="grid2">
            <label>
              Workspace
              <select value={teamId} onChange={(e)=>setTeamId(e.target.value)} style={{marginTop:6}}>
                {!teams.length && <option>No installs yet</option>}
                {teams.map(t=> <option key={t.teamId} value={t.teamId}>{t.teamName} ({t.teamId})</option>)}
              </select>
              {!teams.length && (
                <div className="hint" style={{marginTop:6}}>
                  No workspaces detected. If you recently restarted the server, re-click “Add to Slack” to reinstall and repopulate the list.
                </div>
              )}
            </label>
            <label>
              Recipient emails (comma-separated)
              <input
                type="text"
                value={emails}
                onChange={(e)=>setEmails(e.target.value)}
                placeholder="alice@acme.com, bob@acme.com"
                style={{marginTop:6}}
              />
            </label>
          </div>

          {!!teams.length && (
            <div className="workspace-list">
              {teams.map(t => (
                <span key={t.teamId} className="workspace-pill">
                  <span>Installed</span>
                  <strong>{t.teamName}</strong>
                </span>
              ))}
            </div>
          )}

          <div className="slack-actions" style={{marginTop:10}}>
            <button
              className="btn"
              onClick={async()=>{ if(!link) await createPaste(); if(link || text || file) sendSlack(); }}
              disabled={!teamId || !emails.trim() || sending}
            >
              {sending ? "Sending…" : "Send link via Slack"}
            </button>

            <button className="btn ghost" onClick={()=>window.open(`${API_BASE}/slack/install`, "_blank")}>
              Install another workspace
            </button>

            <button className="btn ghost" onClick={loadTeams}>
              Refresh workspaces
            </button>
          </div>
        </section>
      </div>
    </>
  );
}
