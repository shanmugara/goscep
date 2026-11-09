package webui

import (
	"bytes"
	"crypto/subtle"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

//go:embed templates/*.html static/*
var assets embed.FS

var Logger = logrus.New()

const (
	maxFormBytes   = 1 << 20
	maxCSRBytes    = 64 << 10
	maxLoginFails  = 5
	loginLockout   = 15 * time.Minute
	pemCSRType     = "CERTIFICATE REQUEST"
	pemCSRTypeOld  = "NEW CERTIFICATE REQUEST"
	contentSecPol  = "default-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	genericFailMsg = "The certificate service is unavailable. Please try again later."
)

type Server struct {
	users   *UserStore
	signer  Signer
	sess    *sessions
	limiter *loginLimiter
	pages   map[string]*template.Template
	now     func() time.Time
}

func NewServer(users *UserStore, signer Signer, sessionKey []byte, sessionTTL time.Duration) (*Server, error) {
	if len(sessionKey) < 32 {
		return nil, errors.New("session key must be at least 32 bytes")
	}
	pages := map[string]*template.Template{}
	for _, name := range []string{"login", "index", "result"} {
		t, err := template.ParseFS(assets, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s template: %w", name, err)
		}
		pages[name] = t
	}
	return &Server{
		users:   users,
		signer:  signer,
		sess:    &sessions{key: sessionKey, ttl: sessionTTL},
		limiter: newLoginLimiter(maxLoginFails, loginLockout),
		pages:   pages,
		now:     time.Now,
	}, nil
}

func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(assets, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.requireAuth(s.logout))
	mux.HandleFunc("GET /{$}", s.requireAuth(s.index))
	mux.HandleFunc("POST /submit", s.requireAuth(s.submit))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecPol)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type pageData struct {
	Title    string
	User     string
	CSRF     string
	Error    string
	Username string
	Domains  []string
	Example  string
	CSRText  string
	Cert     *issuedCert
}

type issuedCert struct {
	Subject  string
	Names    []string
	Serial   string
	NotAfter string
	PEM      string
	Lines    int
	FileName string
	DataURL  template.URL
}

func (s *Server) render(w http.ResponseWriter, status int, page string, data pageData) {
	var buf bytes.Buffer
	if err := s.pages[page].ExecuteTemplate(&buf, "layout", data); err != nil {
		Logger.WithError(err).Errorf("Failed to render %s page", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) setSessionCookie(w http.ResponseWriter, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

type authedHandler func(w http.ResponseWriter, r *http.Request, u User)

// requireAuth checks the session cookie, re-checks the user still exists in users.yaml,
// verifies the CSRF token on POSTs and slides the session expiry.
func (s *Server) requireAuth(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		now := s.now()
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		username, expires, ok := s.sess.verify(c.Value, now)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		u, ok := s.users.Get(username)
		if !ok {
			s.setSessionCookie(w, "", time.Unix(0, 0))
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
			token := r.FormValue("csrf")
			if subtle.ConstantTimeCompare([]byte(token), []byte(s.sess.csrf(u.Username))) != 1 {
				Logger.WithFields(logrus.Fields{"user": u.Username, "ip": clientIP(r)}).Warn("Rejected request with invalid CSRF token")
				http.Error(w, "invalid or missing form token, reload the page and try again", http.StatusForbidden)
				return
			}
		}
		if expires.Sub(now) < s.sess.ttl/2 {
			token, exp := s.sess.issue(u.Username, now)
			s.setSessionCookie(w, token, exp)
		}
		next(w, r, u)
	}
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "login", pageData{Title: "Sign in"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	ip := clientIP(r)
	key := ip + "|" + strings.ToLower(username)
	log := Logger.WithFields(logrus.Fields{"event": "login", "user": username, "ip": ip})
	now := s.now()

	if s.limiter.blocked(key, now) {
		log.Warn("Login blocked: too many failed attempts")
		s.render(w, http.StatusTooManyRequests, "login", pageData{Title: "Sign in", Username: username,
			Error: "Too many failed sign-in attempts. Try again later."})
		return
	}
	u, ok := s.users.Authenticate(username, password)
	if !ok {
		s.limiter.fail(key, now)
		log.Warn("Login failed")
		s.render(w, http.StatusUnauthorized, "login", pageData{Title: "Sign in", Username: username,
			Error: "Invalid username or password."})
		return
	}
	s.limiter.reset(key)
	token, exp := s.sess.issue(u.Username, now)
	s.setSessionCookie(w, token, exp)
	log.Info("Login succeeded")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, u User) {
	s.setSessionCookie(w, "", time.Unix(0, 0))
	Logger.WithFields(logrus.Fields{"event": "logout", "user": u.Username, "ip": clientIP(r)}).Info("Logged out")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) indexData(u User) pageData {
	return pageData{
		Title:   "Request a certificate",
		User:    u.Username,
		CSRF:    s.sess.csrf(u.Username),
		Domains: u.AllowedDomains,
		Example: "host." + u.AllowedDomains[0],
	}
}

func (s *Server) index(w http.ResponseWriter, r *http.Request, u User) {
	s.render(w, http.StatusOK, "index", s.indexData(u))
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request, u User) {
	log := Logger.WithFields(logrus.Fields{"event": "issue", "user": u.Username, "ip": clientIP(r)})
	fail := func(status int, csrText, msg string) {
		d := s.indexData(u)
		d.Error = msg
		d.CSRText = csrText
		s.render(w, status, "index", d)
	}

	raw, err := readCSRInput(r)
	if err != nil {
		log.WithError(err).Warn("Rejected CSR input")
		fail(http.StatusBadRequest, "", err.Error())
		return
	}
	// only echo pasted text back into the form, never uploaded binary
	echo := ""
	if bytes.Contains(raw, []byte("-----BEGIN")) {
		echo = string(raw)
	}

	csr, err := parseCSR(raw)
	if err != nil {
		log.WithError(err).Warn("Rejected unparseable CSR")
		fail(http.StatusBadRequest, echo, "That is not a valid certificate signing request. Paste the PEM text starting with -----BEGIN CERTIFICATE REQUEST-----.")
		return
	}
	names := csrNames(csr)
	log = log.WithField("names", names)
	if err := checkCSR(csr, names, u.AllowedDomains); err != nil {
		log.WithError(err).Warn("Rejected CSR")
		fail(http.StatusForbidden, echo, err.Error())
		return
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: pemCSRType, Bytes: csr.Raw})
	certPEM, err := s.signer.Sign(r.Context(), csrPEM, u.Username)
	if err != nil {
		var rej *RejectedError
		if errors.As(err, &rej) {
			log.WithError(err).Warn("goscep rejected CSR")
			fail(http.StatusBadRequest, echo, "The certificate service rejected the request: "+rej.Message)
			return
		}
		log.WithError(err).Error("Certificate issuance failed")
		fail(http.StatusBadGateway, echo, genericFailMsg)
		return
	}

	cert, err := describeCert(certPEM)
	if err != nil {
		log.WithError(err).Error("goscep returned an unparseable certificate")
		fail(http.StatusBadGateway, echo, genericFailMsg)
		return
	}
	log.WithField("serial", cert.Serial).Info("Certificate issued")
	s.render(w, http.StatusOK, "result", pageData{
		Title: "Certificate issued",
		User:  u.Username,
		CSRF:  s.sess.csrf(u.Username),
		Cert:  cert,
	})
}

// readCSRInput returns the uploaded file if one was chosen, otherwise the pasted text.
func readCSRInput(r *http.Request) ([]byte, error) {
	if err := r.ParseMultipartForm(maxFormBytes); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return nil, errors.New("could not read the form; the upload may be too large")
	}
	f, _, err := r.FormFile("csrfile")
	switch {
	case err == nil:
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, maxCSRBytes+1))
		if err != nil {
			return nil, errors.New("could not read the uploaded file")
		}
		if len(data) > maxCSRBytes {
			return nil, errors.New("the uploaded file is too large to be a CSR")
		}
		if len(bytes.TrimSpace(data)) > 0 {
			return data, nil
		}
	case !errors.Is(err, http.ErrMissingFile):
		return nil, errors.New("could not read the uploaded file")
	}
	text := strings.TrimSpace(r.FormValue("csr"))
	if text == "" {
		return nil, errors.New("paste a CSR or choose a CSR file")
	}
	if len(text) > maxCSRBytes {
		return nil, errors.New("the pasted text is too large to be a CSR")
	}
	return []byte(text), nil
}

// parseCSR accepts PEM ("CERTIFICATE REQUEST" or the older "NEW CERTIFICATE REQUEST")
// or raw DER, and checks the CSR's self-signature.
func parseCSR(data []byte) (*x509.CertificateRequest, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != pemCSRType && block.Type != pemCSRTypeOld {
			return nil, fmt.Errorf("PEM block is %q, not a certificate request", block.Type)
		}
		der = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature is invalid: %w", err)
	}
	return csr, nil
}

// csrNames returns the CN and DNS SANs, deduplicated, matching what goscep will issue
// (goscep copies the CN into the SANs when the CSR has none).
func csrNames(csr *x509.CertificateRequest) []string {
	seen := map[string]bool{}
	var names []string
	for _, n := range append([]string{csr.Subject.CommonName}, csr.DNSNames...) {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	return names
}

func checkCSR(csr *x509.CertificateRequest, names, domains []string) error {
	if len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 || len(csr.EmailAddresses) > 0 {
		return errors.New("IP address, URI and email SANs are not supported; request DNS names only")
	}
	if len(names) == 0 {
		return errors.New("the CSR has no common name or DNS names")
	}
	var denied []string
	for _, n := range names {
		if !nameAllowed(n, domains) {
			denied = append(denied, n)
		}
	}
	if len(denied) > 0 {
		return fmt.Errorf("you are not allowed to request %s (allowed domains: %s)",
			strings.Join(denied, ", "), strings.Join(domains, ", "))
	}
	return nil
}

var unsafeFileChars = regexp.MustCompile(`[^a-z0-9.-]+`)

func describeCert(certPEM []byte) (*issuedCert, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	base := strings.Trim(unsafeFileChars.ReplaceAllString(strings.ToLower(cert.Subject.CommonName), "_"), "._")
	if base == "" {
		base = "certificate"
	}
	return &issuedCert{
		Subject:  cert.Subject.String(),
		Names:    cert.DNSNames,
		Serial:   fmt.Sprintf("%X", cert.SerialNumber),
		NotAfter: cert.NotAfter.UTC().Format("2006-01-02 15:04 MST"),
		PEM:      string(certPEM),
		Lines:    strings.Count(strings.TrimSpace(string(certPEM)), "\n") + 1,
		FileName: base + ".crt",
		DataURL:  template.URL("data:application/x-pem-file;base64," + base64.StdEncoding.EncodeToString(certPEM)),
	}, nil
}
