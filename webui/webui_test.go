package webui

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"html"
	"io"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shanmugara/goscep/scep"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

func TestNameAllowed(t *testing.T) {
	domains := []string{"omegaworld.net"}
	cases := map[string]bool{
		"omegaworld.net":          true,
		"host.omegaworld.net":     true,
		"a.b.omegaworld.net":      true,
		"HOST.OmegaWorld.net.":    true,
		"*.omegaworld.net":        true,
		"evilomegaworld.net":      false,
		"omegaworld.net.evil.com": false,
		"other.com":               false,
		"":                        false,
	}
	for name, want := range cases {
		if got := nameAllowed(name, domains); got != want {
			t.Errorf("nameAllowed(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestSessions(t *testing.T) {
	s := &sessions{key: bytes.Repeat([]byte("k"), 32), ttl: time.Hour}
	now := time.Now()
	tok, _ := s.issue("alice", now)

	if u, _, ok := s.verify(tok, now); !ok || u != "alice" {
		t.Fatalf("valid token rejected: %q %v", u, ok)
	}
	if _, _, ok := s.verify(tok, now.Add(2*time.Hour)); ok {
		t.Error("expired token accepted")
	}
	forged := strings.Replace(tok, tok[:5], "Ym9i.", 1) // swap username to "bob"
	if _, _, ok := s.verify(forged, now); ok {
		t.Error("tampered token accepted")
	}
	other := &sessions{key: bytes.Repeat([]byte("x"), 32), ttl: time.Hour}
	if _, _, ok := other.verify(tok, now); ok {
		t.Error("token accepted under a different key")
	}
}

// testPKI is a throwaway CA plus the files goscep and the web UI need.
type testPKI struct {
	dir    string
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPath string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &testPKI{dir: dir, ca: ca, caKey: key, caPath: filepath.Join(dir, "ca.crt")}
	writePEM(t, p.caPath, "CERTIFICATE", der)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	writePEM(t, filepath.Join(dir, "ca.key"), "PRIVATE KEY", keyDER)
	return p
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
}

// leaf writes <name>.crt and <name>.key signed by the test CA.
func (p *testPKI) leaf(t *testing.T, name, cn string, eku x509.ExtKeyUsage) (certPath, keyPath string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{cn},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(p.dir, name+".crt"), filepath.Join(p.dir, name+".key")
	writePEM(t, certPath, "CERTIFICATE", der)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)
	return certPath, keyPath
}

func makeCSR(t *testing.T, cn string, sans ...string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// startGoscep runs goscep's real 8443 handler and TLS config (client-cert CN allowlist).
func startGoscep(t *testing.T, p *testPKI, allowedCN string) string {
	t.Helper()
	srvCert, srvKey := p.leaf(t, "goscep-tls", "localhost", x509.ExtKeyUsageServerAuth)
	allowed := filepath.Join(p.dir, "allowedcns.yaml")
	os.WriteFile(allowed, []byte("allowedcns:\n  - "+allowedCN+"\n"), 0600)

	scep.Logger = logrus.New()
	scep.Logger.SetLevel(logrus.PanicLevel)
	scep.Config = &scep.ServerConfig{
		CARoot:            p.caPath,
		CARootKey:         filepath.Join(p.dir, "ca.key"),
		TlsCert:           srvCert,
		TlsKey:            srvKey,
		ValidityYears:     1,
		AuthorizedDomains: []string{"omegaworld.net", "example.org"},
		AllowedCNs:        allowed,
	}
	tlsCfg, err := scep.BuildTlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.POST("/v1/cert/request", scep.Request(scep.ListenerTLS))
	ts := httptest.NewUnstartedServer(r)
	ts.TLS = tlsCfg
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts.URL + "/v1/cert/request"
}

type uiClient struct {
	t    *testing.T
	base string
	http *http.Client
}

func (c *uiClient) do(req *http.Request) (int, string) {
	c.t.Helper()
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (c *uiClient) get(path string) (int, string) {
	req, _ := http.NewRequest(http.MethodGet, c.base+path, nil)
	return c.do(req)
}

func (c *uiClient) login(user, pass string) (int, string) {
	req, _ := http.NewRequest(http.MethodPost, c.base+"/login",
		strings.NewReader(url.Values{"username": {user}, "password": {pass}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}

func (c *uiClient) submit(csrf string, csrText string, file []byte) (int, string) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	w.WriteField("csrf", csrf)
	w.WriteField("csr", csrText)
	if file != nil {
		fw, _ := w.CreateFormFile("csrfile", "host.csr")
		fw.Write(file)
	}
	w.Close()
	req, _ := http.NewRequest(http.MethodPost, c.base+"/submit", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return c.do(req)
}

var (
	csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	paneRe = regexp.MustCompile(`(?s)<textarea id="pem"[^>]*rows="(\d+)"[^>]*>(.*?)</textarea>`)
)

func TestWebUIEndToEnd(t *testing.T) {
	Logger.SetLevel(logrus.PanicLevel)
	p := newTestPKI(t)
	goscepURL := startGoscep(t, p, "goscep-webui.omegaworld.net")

	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.MinCost)
	usersPath := filepath.Join(p.dir, "users.yaml")
	os.WriteFile(usersPath, []byte("users:\n"+
		"  - username: alice\n    password_hash: \""+string(hash)+"\"\n    allowed_domains: [omegaworld.net]\n"+
		"  - username: bob\n    password_hash: \""+string(hash)+"\"\n    allowed_domains: [web.omegaworld.net]\n"), 0600)
	users, err := NewUserStore(usersPath)
	if err != nil {
		t.Fatal(err)
	}

	clientCert, clientKey := p.leaf(t, "webui-client", "goscep-webui.omegaworld.net", x509.ExtKeyUsageClientAuth)
	client, err := NewGoscepClient(goscepURL, clientCert, clientKey, p.caPath)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(users, client, bytes.Repeat([]byte("s"), 32), 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ui := httptest.NewTLSServer(srv.Handler())
	defer ui.Close()

	newClient := func() *uiClient {
		jar, _ := cookiejar.New(nil)
		hc := ui.Client()
		hc.Jar = jar
		return &uiClient{t: t, base: ui.URL, http: hc}
	}

	t.Run("unauthenticated redirects to login", func(t *testing.T) {
		c := newClient()
		code, body := c.get("/")
		if code != 200 || !strings.Contains(body, "Sign in") {
			t.Fatalf("got %d, want the login page", code)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		c := newClient()
		if code, body := c.login("alice", "nope"); code != 401 || !strings.Contains(body, "Invalid username or password") {
			t.Fatalf("got %d", code)
		}
		if code, _ := c.login("nobody", "nope"); code != 401 {
			t.Fatalf("unknown user got %d", code)
		}
	})

	c := newClient()
	code, body := c.login("alice", "correct-horse")
	if code != 200 || !strings.Contains(body, "Request a certificate") {
		t.Fatalf("login: got %d", code)
	}
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no csrf token on index page")
	}
	csrf := m[1]

	t.Run("missing csrf is rejected", func(t *testing.T) {
		if code, _ := c.submit("", string(makeCSR(t, "host.omegaworld.net")), nil); code != 403 {
			t.Fatalf("got %d, want 403", code)
		}
	})

	t.Run("pasted CSR is issued through 8443", func(t *testing.T) {
		code, body := c.submit(csrf, string(makeCSR(t, "host.omegaworld.net", "host.omegaworld.net", "www.omegaworld.net")), nil)
		if code != 200 || !strings.Contains(body, "Certificate issued") || !strings.Contains(body, "BEGIN CERTIFICATE") {
			t.Fatalf("got %d: %s", code, body)
		}
		if !strings.Contains(body, `download="host.omegaworld.net.crt"`) || !strings.Contains(body, "data:application/x-pem-file;base64,") {
			t.Error("download link missing")
		}
		m := paneRe.FindStringSubmatch(body)
		if m == nil {
			t.Fatal("certificate pane missing")
		}
		paneText := html.UnescapeString(m[2])
		block, _ := pem.Decode([]byte(paneText))
		if block == nil {
			t.Fatal("pane does not contain a PEM certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || cert.Subject.CommonName != "host.omegaworld.net" {
			t.Fatalf("pane certificate: %v", err)
		}
		if want := strconv.Itoa(strings.Count(strings.TrimSpace(paneText), "\n") + 1); m[1] != want {
			t.Errorf("pane rows = %s, want %s so the whole certificate is visible", m[1], want)
		}
		if !strings.Contains(body, `data-copy="pem"`) {
			t.Error("copy button missing")
		}
		if code, js := c.get("/static/app.js"); code != 200 || !strings.Contains(js, "clipboard") {
			t.Errorf("app.js: %d", code)
		}
	})

	t.Run("uploaded DER CSR is issued", func(t *testing.T) {
		block, _ := pem.Decode(makeCSR(t, "api.omegaworld.net"))
		if code, body := c.submit(csrf, "", block.Bytes); code != 200 || !strings.Contains(body, "Certificate issued") {
			t.Fatalf("got %d: %s", code, body)
		}
	})

	t.Run("names outside the user's domains are refused", func(t *testing.T) {
		for _, csr := range [][]byte{
			makeCSR(t, "host.example.org"),                        // goscep would allow example.org; alice may not
			makeCSR(t, "evilomegaworld.net"),                      // suffix without a dot boundary
			makeCSR(t, "host.omegaworld.net", "host.example.org"), // one bad SAN
		} {
			if code, body := c.submit(csrf, string(csr), nil); code != 403 || !strings.Contains(body, "not allowed") {
				t.Errorf("got %d", code)
			}
		}
	})

	t.Run("garbage input", func(t *testing.T) {
		if code, _ := c.submit(csrf, "/etc/hosts", nil); code != 400 {
			t.Fatalf("got %d", code)
		}
		if code, _ := c.submit(csrf, "", nil); code != 400 {
			t.Fatalf("got %d", code)
		}
	})

	t.Run("bob is limited to web.omegaworld.net", func(t *testing.T) {
		b := newClient()
		_, body := b.login("bob", "correct-horse")
		bcsrf := csrfRe.FindStringSubmatch(body)[1]
		if bcsrf == csrf {
			t.Error("csrf tokens should differ per user")
		}
		if code, _ := b.submit(bcsrf, string(makeCSR(t, "app.web.omegaworld.net")), nil); code != 200 {
			t.Errorf("allowed name got %d", code)
		}
		if code, _ := b.submit(bcsrf, string(makeCSR(t, "host.omegaworld.net")), nil); code != 403 {
			t.Errorf("parent domain got %d", code)
		}
		if code, _ := b.submit(csrf, string(makeCSR(t, "app.web.omegaworld.net")), nil); code != 403 {
			t.Errorf("alice's csrf token accepted for bob: %d", code)
		}
	})

	t.Run("lockout after repeated failures", func(t *testing.T) {
		l := newClient()
		for range maxLoginFails {
			l.login("alice", "wrong")
		}
		if code, _ := l.login("alice", "correct-horse"); code != 429 {
			t.Fatalf("got %d, want 429", code)
		}
	})

	t.Run("removed user loses their session", func(t *testing.T) {
		time.Sleep(10 * time.Millisecond) // ensure a new mtime
		os.WriteFile(usersPath, []byte("users:\n  - username: bob\n    password_hash: \""+string(hash)+"\"\n    allowed_domains: [web.omegaworld.net]\n"), 0600)
		future := time.Now().Add(time.Second)
		os.Chtimes(usersPath, future, future)
		if code, body := c.get("/"); code != 200 || !strings.Contains(body, "Sign in") {
			t.Fatalf("got %d, want the login page", code)
		}
	})

	t.Run("logout", func(t *testing.T) {
		b := newClient()
		_, body := b.login("bob", "correct-horse")
		bcsrf := csrfRe.FindStringSubmatch(body)[1]
		req, _ := http.NewRequest(http.MethodPost, ui.URL+"/logout", strings.NewReader(url.Values{"csrf": {bcsrf}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		b.do(req)
		if _, body := b.get("/"); !strings.Contains(body, "Sign in") {
			t.Fatal("still signed in after logout")
		}
	})
}

func TestGoscepRejectsUnlistedWebUICert(t *testing.T) {
	p := newTestPKI(t)
	goscepURL := startGoscep(t, p, "goscep-webui.omegaworld.net")
	cert, key := p.leaf(t, "other", "someone-else.omegaworld.net", x509.ExtKeyUsageClientAuth)
	client, err := NewGoscepClient(goscepURL, cert, key, p.caPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Sign(t.Context(), makeCSR(t, "host.omegaworld.net"), "alice")
	if err == nil || !strings.Contains(err.Error(), "bad certificate") {
		t.Fatalf("want TLS rejection, got %v", err)
	}
}
