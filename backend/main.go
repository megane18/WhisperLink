package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

/*
  Zero-knowledge server:
  - Accepts only ciphertext, nonce, alg (+optional salt/kdf for password mode) from the client.
  - Enforces TTL, burn-after-read, max reads.
  - Tracks simple per-IP fetch/consume counts.
  - Includes per-IP rate limiting middleware.
  - Multi-tenant Slack OAuth; stores per-team bot tokens in memory.
*/

var b64 = base64.RawURLEncoding

type KDFInfo struct {
	Name       string `json:"name,omitempty"`       // "PBKDF2"
	Iterations int    `json:"iterations,omitempty"` // e.g. 100000
	Digest     string `json:"digest,omitempty"`     // "SHA-256"
}

// Client → server when creating a paste (ciphertext-only)
type createReq struct {
	Ciphertext string   `json:"ciphertext"`           // base64url
	Nonce      string   `json:"nonce"`                // base64url
	Alg        string   `json:"alg"`                  // "AES-256-GCM"
	Salt       string   `json:"salt,omitempty"`       // base64url (password mode)
	KDF        *KDFInfo `json:"kdf,omitempty"`        // password mode params
	Meta       *struct {
		Filename string `json:"filename,omitempty"`
		Mime     string `json:"mime,omitempty"`
	} `json:"meta,omitempty"`

	TTLSeconds    *int  `json:"ttlSeconds,omitempty"`    // default 3600
	BurnAfterRead *bool `json:"burnAfterRead,omitempty"` // default false
	MaxReads      *int  `json:"maxReads,omitempty"`      // default 1 (min 1)
}

type createResp struct {
	URL string `json:"url"`
	ID  string `json:"id"`
}

// Server → client when reading metadata
type readResp struct {
	Ciphertext string   `json:"ciphertext"`
	Nonce      string   `json:"nonce"`
	Alg        string   `json:"alg"`
	Salt       string   `json:"salt,omitempty"`
	KDF        *KDFInfo `json:"kdf,omitempty"`
	Meta       *struct {
		Filename string `json:"filename,omitempty"`
		Mime     string `json:"mime,omitempty"`
		Size     int    `json:"size,omitempty"`
	} `json:"meta,omitempty"`

	ExpiresAt int64 `json:"expiresAt"`
	Burn      bool  `json:"burn"`
	ReadsLeft int   `json:"readsLeft"`
}

type storedPaste struct {
	Ciphertext string
	Nonce      string
	Alg        string
	Salt       string
	KDF        *KDFInfo
	Meta       *struct {
		Filename string
		Mime     string
		Size     int
	}

	CreatedAt time.Time
	ExpiresAt time.Time
	Burn      bool
	MaxReads  int
	ReadsUsed int

	FetchIPs   map[string]int // GET meta
	ConsumeIPs map[string]int // POST consume
}

var (
	storeMu sync.RWMutex
	store   = map[string]*storedPaste{}
)

func defaultBool(p *bool, def bool) bool { if p == nil { return def } ; return *p }
func defaultInt(p *int, def int) int     { if p == nil { return def } ; return *p }

func genID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil { return "", err }
	return hex.EncodeToString(b), nil
}

func isExpired(p *storedPaste) bool { return !p.ExpiresAt.IsZero() && time.Now().After(p.ExpiresAt) }
func imax(a, b int) int             { if a > b { return a } ; return b }

func portOr(def string) string {
	if p := os.Getenv("PORT"); p != "" { return p }
	return def
}

// Build base URL: env BASE_URL > proxy headers > request host
func effectiveBaseURL(c *gin.Context) string {
	if base := os.Getenv("BASE_URL"); base != "" {
		return strings.TrimRight(base, "/")
	}
	scheme := c.Request.Header.Get("X-Forwarded-Proto")
	host := c.Request.Header.Get("X-Forwarded-Host")
	if scheme == "" {
		if c.Request.TLS != nil { scheme = "https" } else { scheme = "http" }
	}
	if host == "" { host = c.Request.Host }
	if host == "" { host = "localhost:" + portOr("8080") }
	return scheme + "://" + host
}

// -------- Rate limiting (per-IP token bucket) --------

type visitor struct {
	tokens float64
	last   time.Time
}

var (
	visitorsMu sync.Mutex
	visitors   = map[string]*visitor{}
	rateRPS    = 1.5  // avg requests/sec
	burst      = 10.0 // burst capacity
)

func rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := clientIP(c)
		now := time.Now()

		visitorsMu.Lock()
		v := visitors[ip]
		if v == nil {
			v = &visitor{tokens: burst, last: now}
			visitors[ip] = v
		}
		elapsed := now.Sub(v.last).Seconds()
		v.tokens = minF(burst, v.tokens+elapsed*rateRPS)
		v.last = now

		if v.tokens < 1.0 {
			visitorsMu.Unlock()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit"})
			return
		}
		v.tokens -= 1.0
		visitorsMu.Unlock()

		c.Next()
	}
}

func minF(a, b float64) float64 { if a < b { return a } ; return b }

func clientIP(c *gin.Context) string {
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 { return strings.TrimSpace(parts[0]) }
	}
	ip, _, err := net.SplitHostPort(strings.TrimSpace(c.Request.RemoteAddr))
	if err == nil && ip != "" { return ip }
	return c.ClientIP()
}

// -------- Inline read page (client-side decrypt; supports password mode) --------

const readPage = `<!doctype html>
<html>
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Secure Paste – Read</title>
<style>
:root{color-scheme:light dark}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;margin:2rem;line-height:1.45}
pre{background:Canvas;padding:1rem;border:1px solid ButtonBorder;border-radius:10px;overflow:auto}
.err{color:#b00020}.muted{color:#666}
label,input,button{font:inherit}
button{padding:.5rem 1rem}
input[type=password]{padding:.4rem .6rem;border:1px solid ButtonBorder;border-radius:8px}
</style>
</head>
<body>
<h1>🔐 Decrypt Secret</h1>
<p class="muted">Zero-knowledge: server stores only ciphertext. Key stays in the URL fragment or is derived from your password.</p>

<div id="pwRow" style="display:none;margin:.5rem 0 1rem 0">
  <label>Password: <input id="pw" type="password" /></label>
  <button id="decBtn">Decrypt</button>
</div>

<div id="status">Loading…</div>
<pre id="output" style="display:none"></pre>
<pre id="error" class="err" style="display:none"></pre>

<script>
const b64uToBytes = (s)=>{const pad=(s.length%4)?4-(s.length%4):0;const n=s+"=".repeat(pad);const b64=n.replace(/-/g,"+").replace(/_/g,"/");const bin=atob(b64);const out=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);return out;}
const bytesToStr = (ab)=>new TextDecoder().decode(new Uint8Array(ab));

async function deriveKeyFromPassword(pw, salt, iterations){
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(pw), {name:"PBKDF2"}, false, ["deriveKey"]);
  return await crypto.subtle.deriveKey(
    {name:"PBKDF2", salt, iterations, hash:"SHA-256"},
    baseKey,
    {name:"AES-GCM", length:256},
    false,
    ["decrypt"]
  );
}

(async () => {
  const status = document.getElementById('status');
  const out = document.getElementById('output');
  const err = document.getElementById('error');
  const pwRow = document.getElementById('pwRow');
  const pwInput = document.getElementById('pw');
  const decBtn = document.getElementById('decBtn');

  try {
    const parts=location.pathname.split('/').filter(Boolean);
    const id=parts[1]; // /read/:id
    const hash=location.hash.startsWith('#')?location.hash.slice(1):"";

    status.textContent="Fetching…";
    const metaRes=await fetch("/api/paste/"+encodeURIComponent(id));
    if(!metaRes.ok) throw new Error("Server returned " + metaRes.status);
    const meta=await metaRes.json();

    let key;
    if(hash){
      key = await crypto.subtle.importKey("raw", b64uToBytes(hash), "AES-GCM", false, ["decrypt"]);
    }else if(meta.kdf && meta.salt){
      pwRow.style.display="block";
      await new Promise((resolve,reject)=>{
        decBtn.onclick = async ()=>{
          try{
            status.textContent="Deriving key…"; status.style.display="block";
            const salt=b64uToBytes(meta.salt);
            const iterations = meta.kdf.iterations || 100000;
            key = await deriveKeyFromPassword(pwInput.value, salt, iterations);
            resolve();
          }catch(e){ reject(e); }
        };
      });
    }else{
      throw new Error("Missing key. Open link with fragment or use password.");
    }

    status.textContent="Decrypting…";
    const ct=b64uToBytes(meta.ciphertext);
    const iv=b64uToBytes(meta.nonce);
    const pt=await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ct);
    status.style.display="none";
    out.style.display="block";
    out.textContent=bytesToStr(pt);

    try { await fetch("/api/paste/"+encodeURIComponent(id)+"/consume", {method:"POST"}); } catch {}

  } catch(e){
    document.getElementById('status').style.display="none";
    err.style.display="block";
    err.textContent="Error: " + (e && e.message ? e.message : e);
  }
})();
</script>
</body>
</html>`

// -------- Slack (multi-tenant) minimal helpers --------

type slackInstall struct {
	TeamID    string
	TeamName  string
	BotToken  string // xoxb-…
	Installed time.Time
}

var (
	instMu   sync.RWMutex
	installs = map[string]*slackInstall{}
)

func saveInstall(teamID, teamName, botToken string) {
	instMu.Lock()
	installs[teamID] = &slackInstall{TeamID: teamID, TeamName: teamName, BotToken: botToken, Installed: time.Now()}
	instMu.Unlock()
}
func botTokenForTeam(teamID string) (string, bool) {
	instMu.RLock()
	i, ok := installs[teamID]
	instMu.RUnlock()
	if !ok { return "", false }
	return i.BotToken, true
}

func slackSigningSecret() string { return os.Getenv("SLACK_SIGNING_SECRET") }

func verifySlackSignature(c *gin.Context) bool {
	secret := slackSigningSecret()
	if secret == "" { return false }
	if c.Request == nil { return false }
	ts := c.GetHeader("X-Slack-Request-Timestamp")
	sig := c.GetHeader("X-Slack-Signature")
	if ts == "" || sig == "" { return false }
	bodyBytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil { return false }
	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	base := "v0:" + ts + ":" + string(bodyBytes)
	mac := hmac.New(sha256.New, []byte(secret)); mac.Write([]byte(base))
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

// Generic JSON POST helper
func slackAPIWithToken(ctx context.Context, token, method string, payload interface{}) (*http.Response, []byte, error) {
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://slack.com/api/"+method, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, nil, err }
	body, _ := ioutil.ReadAll(resp.Body); resp.Body.Close()
	return resp, body, nil
}

// NEW: GET helper for Slack methods that require query params (e.g., users.lookupByEmail)
func slackAPIGetWithToken(ctx context.Context, token, method string, params map[string]string) (*http.Response, []byte, error) {
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	endpoint := "https://slack.com/api/" + method + "?" + q.Encode()
	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body, nil
}

func slackOpenIMWithToken(ctx context.Context, token, userID string) (string, error) {
	resp, body, err := slackAPIWithToken(ctx, token, "conversations.open", map[string]any{"users": userID})
	if err != nil { return "", err }
	var out struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Channel struct{ ID string `json:"id"` } `json:"channel"`
	}
	if err := json.Unmarshal(body, &out); err != nil || resp.StatusCode != 200 || !out.OK {
		if err != nil { return "", fmt.Errorf("open im decode: %v body=%s", err, string(body)) }
		return "", fmt.Errorf("open im: %s body=%s", out.Error, string(body))
	}
	return out.Channel.ID, nil
}

func slackPostMessageWithToken(ctx context.Context, token, channelID, text string) error {
	resp, body, err := slackAPIWithToken(ctx, token, "chat.postMessage", map[string]any{"channel": channelID, "text": text})
	if err != nil { return err }
	var out struct{ OK bool `json:"ok"`; Error string `json:"error"` }
	if err := json.Unmarshal(body, &out); err != nil || resp.StatusCode != 200 || !out.OK {
		if err != nil { return fmt.Errorf("post message decode: %v body=%s", err, string(body)) }
		return fmt.Errorf("post message: %s body=%s", out.Error, string(body))
	}
	return nil
}

// FIXED: users.lookupByEmail must be GET with ?email=...
func slackLookupByEmailWithToken(ctx context.Context, token, email string) (string, error) {
	resp, body, err := slackAPIGetWithToken(ctx, token, "users.lookupByEmail", map[string]string{"email": email})
	if err != nil {
		return "", err
	}
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		User  struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &out); err != nil || resp.StatusCode != 200 || !out.OK {
		if err != nil {
			return "", fmt.Errorf("lookup decode: %v body=%s", err, string(body))
		}
		return "", fmt.Errorf("lookup: %s body=%s", out.Error, string(body))
	}
	return out.User.ID, nil
}
func main() {
	_ = godotenv.Load()

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), rateLimitMiddleware())

	_ = r.SetTrustedProxies([]string{"127.0.0.1", "::1"})
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"http://localhost:3000", "http://127.0.0.1:3000"},
		AllowMethods: []string{"GET", "POST", "OPTIONS"},
		AllowHeaders: []string{"Content-Type"},
		MaxAge:       12 * time.Hour,
	}))

	r.GET("/api/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// Create paste (ciphertext-only; <=1MB decoded)
	r.POST("/api/paste", func(c *gin.Context) {
		var req createReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
		}
		if strings.TrimSpace(req.Ciphertext) == "" || strings.TrimSpace(req.Nonce) == "" || req.Alg == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ciphertext, nonce, alg required"}); return
		}
		ctBytes, err := b64.DecodeString(req.Ciphertext)
		if err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": "bad ciphertext"}); return }
		if len(ctBytes) > 1<<20 { // 1 MB
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "payload too large (max 1MB ciphertext)"}); return
		}
		if _, err := b64.DecodeString(req.Nonce); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad nonce"}); return
		}
		ttl := defaultInt(req.TTLSeconds, 3600)
		burn := defaultBool(req.BurnAfterRead, false)
		maxReads := defaultInt(req.MaxReads, 1); if maxReads < 1 { maxReads = 1 }

		id, err := genID()
		if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "id failed"}); return }
		now := time.Now()
		var exp time.Time
		if ttl > 0 { exp = now.Add(time.Duration(ttl) * time.Second) }

		var meta *struct{ Filename, Mime string; Size int }
		if req.Meta != nil {
			meta = &struct{ Filename, Mime string; Size int }{
				Filename: req.Meta.Filename, Mime: req.Meta.Mime, Size: len(ctBytes),
			}
		}

		storeMu.Lock()
		store[id] = &storedPaste{
			Ciphertext: req.Ciphertext,
			Nonce:      req.Nonce,
			Alg:        req.Alg,
			Salt:       req.Salt,
			KDF:        req.KDF,
			Meta:       meta,
			CreatedAt:  now,
			ExpiresAt:  exp,
			Burn:       burn,
			MaxReads:   maxReads,
			ReadsUsed:  0,
			FetchIPs:   map[string]int{},
			ConsumeIPs: map[string]int{},
		}
		storeMu.Unlock()

		base := effectiveBaseURL(c)
		link := fmt.Sprintf("%s/read/%s", base, id)
		c.JSON(http.StatusOK, createResp{URL: link, ID: id})
	})

	// Fetch metadata
	r.GET("/api/paste/:id", func(c *gin.Context) {
		id := c.Param("id")
		ip := clientIP(c)

		storeMu.Lock()
		p, ok := store[id]
		if !ok {
			storeMu.Unlock()
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return
		}
		if isExpired(p) {
			delete(store, id); storeMu.Unlock()
			c.JSON(http.StatusGone, gin.H{"error": "expired"}); return
		}
		if p.ReadsUsed >= p.MaxReads || (p.Burn && p.ReadsUsed >= 1) {
			delete(store, id); storeMu.Unlock()
			c.JSON(http.StatusGone, gin.H{"error": "consumed"}); return
		}
		p.FetchIPs[ip]++
		resp := readResp{
			Ciphertext: p.Ciphertext,
			Nonce:      p.Nonce,
			Alg:        p.Alg,
			Salt:       p.Salt,
			KDF:        p.KDF,
			ExpiresAt:  p.ExpiresAt.Unix(),
			Burn:       p.Burn,
			ReadsLeft:  imax(0, p.MaxReads-p.ReadsUsed),
		}
		if p.Meta != nil {
			resp.Meta = &struct {
				Filename string `json:"filename,omitempty"`
				Mime     string `json:"mime,omitempty"`
				Size     int    `json:"size,omitempty"`
			}{Filename: p.Meta.Filename, Mime: p.Meta.Mime, Size: p.Meta.Size}
		}
		storeMu.Unlock()
		c.JSON(http.StatusOK, resp)
	})

	// Consume after successful decrypt
	r.POST("/api/paste/:id/consume", func(c *gin.Context) {
		id := c.Param("id")
		ip := clientIP(c)

		storeMu.Lock()
		p, ok := store[id]
		if !ok {
			storeMu.Unlock()
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return
		}
		if isExpired(p) {
			delete(store, id); storeMu.Unlock()
			c.JSON(http.StatusGone, gin.H{"error": "expired"}); return
		}
		p.ReadsUsed++
		p.ConsumeIPs[ip]++
		if (p.Burn && p.ReadsUsed >= 1) || p.ReadsUsed >= p.MaxReads {
			delete(store, id)
		}
		storeMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Read page
	r.GET("/read/:id", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(readPage))
	})

	// -------- Slack OAuth (multi-tenant) --------

	r.GET("/slack/install", func(c *gin.Context) {
		clientID := os.Getenv("SLACK_CLIENT_ID")
		if clientID == "" { c.String(500, "SLACK_CLIENT_ID not set"); return }
		redirect := effectiveBaseURL(c) + "/slack/oauth/callback"
		// Needs chat:write, im:write, users:read, users:read.email for DM-by-email
		scopes := "chat:write,im:write,users:read,users:read.email"
		authURL := fmt.Sprintf(
			"https://slack.com/oauth/v2/authorize?client_id=%s&scope=%s&redirect_uri=%s",
			url.QueryEscape(clientID), url.QueryEscape(scopes), url.QueryEscape(redirect),
		)
		c.Redirect(http.StatusFound, authURL)
	})

	r.GET("/slack/oauth/callback", func(c *gin.Context) {
		code := c.Query("code")
		if code == "" { c.String(400, "missing code"); return }

		values := url.Values{}
		values.Set("code", code)
		values.Set("client_id", os.Getenv("SLACK_CLIENT_ID"))
		values.Set("client_secret", os.Getenv("SLACK_CLIENT_SECRET"))
		values.Set("redirect_uri", effectiveBaseURL(c)+"/slack/oauth/callback")

		req, _ := http.NewRequest("POST", "https://slack.com/api/oauth.v2.access", strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil { c.String(502, "oauth exchange failed"); return }
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		var out struct {
			OK          bool   `json:"ok"`
			Error       string `json:"error"`
			AccessToken string `json:"access_token"`
			Team        struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"team"`
		}
		if err := json.Unmarshal(body, &out); err != nil || !out.OK {
			c.String(502, "oauth failed: %s", string(body)); return
		}

		saveInstall(out.Team.ID, out.Team.Name, out.AccessToken)
		c.String(200, "Installed for team %s (%s). You can close this tab.", out.Team.Name, out.Team.ID)
	})

	// List installed teams (for FE dropdown)
	r.GET("/slack/teams", func(c *gin.Context) {
		instMu.RLock()
		list := make([]map[string]string, 0, len(installs))
		for _, ins := range installs {
			list = append(list, map[string]string{"teamId": ins.TeamID, "teamName": ins.TeamName})
		}
		instMu.RUnlock()
		c.JSON(http.StatusOK, list)
	})

	// Optional: dev echo (dry-run)
	r.POST("/dev/slack/share", func(c *gin.Context) {
		var req struct {
			TeamID     string   `json:"teamId"`
			Link       string   `json:"link"`
			Recipients []string `json:"recipients"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
		}
		_, ok := botTokenForTeam(req.TeamID)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "unknown or uninstalled teamId"}); return
		}
		c.JSON(http.StatusOK, gin.H{"url": req.Link, "sent": req.Recipients, "failed": []string{}})
	})

	// REAL Slack share: lookup by email -> open DM -> post
	r.POST("/slack/share", func(c *gin.Context) {
		var req struct {
			TeamID     string   `json:"teamId"`
			Link       string   `json:"link"`
			Recipients []string `json:"recipients"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		token, ok := botTokenForTeam(req.TeamID)
		if !ok || strings.TrimSpace(token) == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "unknown or uninstalled teamId"})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
		defer cancel()

		var sent []string
		var failed []string

		for _, email := range req.Recipients {
			email = strings.TrimSpace(email)
			if email == "" {
				continue
			}

			uid, err := slackLookupByEmailWithToken(ctx, token, email)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s (lookup error: %v)", email, err))
				continue
			}

			ch, err := slackOpenIMWithToken(ctx, token, uid)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s (open DM error: %v)", email, err))
				continue
			}

			text := fmt.Sprintf("🔐 A secret was shared with you:\n%s", req.Link)
			if err := slackPostMessageWithToken(ctx, token, ch, text); err != nil {
				failed = append(failed, fmt.Sprintf("%s (post error: %v)", email, err))
				continue
			}

			sent = append(sent, email)
		}

		c.JSON(http.StatusOK, gin.H{
			"url":    req.Link,
			"sent":   sent,
			"failed": failed,
		})
	})

	// Start server
	r.Run(":" + portOr("8080"))
}
