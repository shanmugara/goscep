package webui

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sessionCookie = "goscep_session"

// sessions issues and verifies HMAC-signed session tokens of the form
// base64url(username) "." expiryUnix "." mac. Nothing is stored server side.
type sessions struct {
	key []byte
	ttl time.Duration
}

func (s *sessions) mac(payload string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *sessions) issue(username string, now time.Time) (token string, expires time.Time) {
	expires = now.Add(s.ttl)
	payload := base64.RawURLEncoding.EncodeToString([]byte(username)) + "." + strconv.FormatInt(expires.Unix(), 10)
	return payload + "." + s.mac(payload), expires
}

func (s *sessions) verify(token string, now time.Time) (username string, expires time.Time, ok bool) {
	i := strings.LastIndexByte(token, '.')
	if i < 0 {
		return "", time.Time{}, false
	}
	payload, sig := token[:i], token[i+1:]
	if !hmac.Equal([]byte(sig), []byte(s.mac(payload))) {
		return "", time.Time{}, false
	}
	userPart, expPart, found := strings.Cut(payload, ".")
	if !found {
		return "", time.Time{}, false
	}
	exp, err := strconv.ParseInt(expPart, 10, 64)
	if err != nil || now.Unix() >= exp {
		return "", time.Time{}, false
	}
	u, err := base64.RawURLEncoding.DecodeString(userPart)
	if err != nil {
		return "", time.Time{}, false
	}
	return string(u), time.Unix(exp, 0), true
}

// csrf returns the per-user token that every POST form must carry.
func (s *sessions) csrf(username string) string {
	return s.mac("csrf|" + username)
}

// loginLimiter locks out an IP+username pair after too many failed logins.
type loginLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	fails  map[string]*loginFailures
}

type loginFailures struct {
	count int
	first time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, fails: map[string]*loginFailures{}}
}

func (l *loginLimiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.fails[key]
	if !ok {
		return false
	}
	if now.Sub(f.first) > l.window {
		delete(l.fails, key)
		return false
	}
	return f.count >= l.max
}

func (l *loginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.fails[key]
	if !ok || now.Sub(f.first) > l.window {
		f = &loginFailures{first: now}
		l.fails[key] = f
	}
	f.count++
	// keep the map bounded under a spray of failed logins
	if len(l.fails) > 10000 {
		for k, v := range l.fails {
			if now.Sub(v.first) > l.window {
				delete(l.fails, k)
			}
		}
	}
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
}
