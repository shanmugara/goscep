package webui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type User struct {
	Username       string   `yaml:"username"`
	PasswordHash   string   `yaml:"password_hash"`
	AllowedDomains []string `yaml:"allowed_domains"`
}

type usersFile struct {
	Users []User `yaml:"users"`
}

// UserStore holds the users from users.yaml and reloads the file when it changes on disk,
// so edits to a mounted file or ConfigMap take effect without a restart.
type UserStore struct {
	path    string
	mu      sync.RWMutex
	modTime time.Time
	users   map[string]User
}

// dummyHash is compared against when the username is unknown, so a login attempt
// takes the same time whether or not the user exists.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("goscep-dummy-password"), bcrypt.DefaultCost)

func NewUserStore(path string) (*UserStore, error) {
	s := &UserStore{path: path}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read users file: %w", err)
	}
	if err := s.load(fi.ModTime()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *UserStore) load(modTime time.Time) error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("failed to read users file %s: %w", s.path, err)
	}
	var f usersFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("failed to parse users file %s: %w", s.path, err)
	}

	users := make(map[string]User, len(f.Users))
	for i, u := range f.Users {
		if u.Username == "" || u.PasswordHash == "" {
			return fmt.Errorf("users file %s: entry %d is missing username or password_hash", s.path, i+1)
		}
		if _, dup := users[u.Username]; dup {
			return fmt.Errorf("users file %s: duplicate user %q", s.path, u.Username)
		}
		if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
			return fmt.Errorf("users file %s: user %q has an invalid bcrypt password_hash", s.path, u.Username)
		}
		domains := make([]string, 0, len(u.AllowedDomains))
		for _, d := range u.AllowedDomains {
			d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".")
			if d == "" {
				return fmt.Errorf("users file %s: user %q has an empty allowed_domains entry", s.path, u.Username)
			}
			domains = append(domains, d)
		}
		if len(domains) == 0 {
			return fmt.Errorf("users file %s: user %q has no allowed_domains", s.path, u.Username)
		}
		u.AllowedDomains = domains
		users[u.Username] = u
	}
	if len(users) == 0 {
		return fmt.Errorf("users file %s: no users defined", s.path)
	}

	s.mu.Lock()
	s.users = users
	s.modTime = modTime
	s.mu.Unlock()
	Logger.Infof("Loaded %d web UI users from %s", len(users), s.path)
	return nil
}

// refresh reloads the users file if its modification time changed. A broken edit is logged
// once and the last good set of users stays in effect.
func (s *UserStore) refresh() {
	fi, err := os.Stat(s.path)
	if err != nil {
		Logger.Warnf("Failed to stat users file, keeping current users: %v", err)
		return
	}
	s.mu.RLock()
	unchanged := fi.ModTime().Equal(s.modTime)
	s.mu.RUnlock()
	if unchanged {
		return
	}
	if err := s.load(fi.ModTime()); err != nil {
		Logger.Errorf("Failed to reload users file, keeping current users: %v", err)
		s.mu.Lock()
		s.modTime = fi.ModTime()
		s.mu.Unlock()
	}
}

func (s *UserStore) Get(username string) (User, bool) {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	return u, ok
}

func (s *UserStore) Authenticate(username, password string) (User, bool) {
	u, ok := s.Get(username)
	hash := dummyHash
	if ok {
		hash = []byte(u.PasswordHash)
	}
	err := bcrypt.CompareHashAndPassword(hash, []byte(password))
	return u, ok && err == nil
}

// nameAllowed reports whether name is one of the domains or a subdomain of one.
// "evilomegaworld.net" does not match "omegaworld.net".
func nameAllowed(name string, domains []string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return false
	}
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}
