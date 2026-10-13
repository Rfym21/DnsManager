package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"golang.org/x/crypto/bcrypt"
)

var ErrConflict = errors.New("resource already exists or has changed")
var ErrForbidden = errors.New("operation is not permitted")

type User struct {
	ID           string          `json:"id"`
	Username     string          `json:"username"`
	Role         string          `json:"role"`
	Enabled      bool            `json:"enabled"`
	TOTPEnabled  bool            `json:"totp_enabled"`
	Preferences  json.RawMessage `json:"preferences"`
	CreatedAt    time.Time       `json:"created_at"`
	PasswordHash string          `json:"-"`
	TOTPSecret   string          `json:"-"`
}

type Principal struct {
	User        User
	DomainID    string
	SessionHash string
	CSRF        string
	Scopes      []string
	Token       bool
	TokenHash   string
}

func (p Principal) Admin() bool { return p.User.Role == "admin" && p.DomainID == "" }
func (p Principal) AllowsScope(scope string) bool {
	if !p.Token {
		return true
	}
	for _, granted := range p.Scopes {
		if granted == scope || granted == "*" {
			return true
		}
	}
	return false
}

const userColumns = "id,username,password_hash,role,enabled,totp_secret,totp_enabled,preferences,created_at"

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var secret sql.NullString
	var preferences []byte
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Enabled, &secret, &u.TOTPEnabled, &preferences, &u.CreatedAt)
	u.Preferences = preferences
	u.TOTPSecret = secret.String
	return u, err
}

func (s *Store) Installed(ctx context.Context) (bool, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count > 0, err
}

// Install serializes initial administrator creation across all API replicas.
func (s *Store) Install(ctx context.Context, username, password string) (User, error) {
	pool := s.LockDB
	if pool == nil {
		pool = s.DB
	}
	release, err := pool.Lock(ctx, []string{"@install"}, 5*time.Second)
	if err != nil {
		return User{}, ErrConflict
	}
	defer release()
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return User{}, err
	}
	defer conn.Close()
	var count int
	if err = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return User{}, err
	}
	if count > 0 {
		return User{}, ErrConflict
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return User{}, err
	}
	id, err := ID()
	if err != nil {
		return User{}, err
	}
	_, err = conn.ExecContext(ctx, "INSERT INTO users (id,username,password_hash,role,enabled,preferences,created_at,updated_at) VALUES (?,?,?,'admin',TRUE,'{}',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))", id, username, string(hash))
	if err != nil {
		return User{}, err
	}
	return s.User(ctx, id)
}

func (s *Store) User(ctx context.Context, id string) (User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id=?", id))
}
func (s *Store) UserByName(ctx context.Context, name string) (User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE LOWER(username)=LOWER(?)", name))
}

func (s *Store) CreateSession(ctx context.Context, u User, domainID string, ttl time.Duration) (string, string, error) {
	token, err := cryptobox.RandomHex(32)
	if err != nil {
		return "", "", err
	}
	csrf, err := cryptobox.RandomHex(32)
	if err != nil {
		return "", "", err
	}
	_, err = s.DB.ExecContext(ctx, "INSERT INTO sessions (token_hash,user_id,domain_id,csrf_token,created_at,expires_at) VALUES (?,?,?,?,UTC_TIMESTAMP(6),?)", cryptobox.Hash(token), u.ID, nullString(domainID), csrf, time.Now().UTC().Add(ttl))
	return token, csrf, err
}

func (s *Store) Session(ctx context.Context, token string) (Principal, error) {
	var p Principal
	var domain sql.NullString
	p.SessionHash = cryptobox.Hash(token)
	err := s.DB.QueryRowContext(ctx, "SELECT user_id,domain_id,csrf_token FROM sessions WHERE token_hash=? AND expires_at>UTC_TIMESTAMP(6)", p.SessionHash).Scan(&p.User.ID, &domain, &p.CSRF)
	if err != nil {
		return p, err
	}
	p.DomainID = domain.String
	p.User, err = s.User(ctx, p.User.ID)
	if err != nil {
		return p, err
	}
	if !p.User.Enabled {
		return p, ErrForbidden
	}
	if p.DomainID != "" {
		var enabled bool
		if err = s.DB.QueryRowContext(ctx, "SELECT quicklogin_enabled FROM domains WHERE id=?", p.DomainID).Scan(&enabled); err != nil || !enabled {
			return p, ErrForbidden
		}
		allowed, e := s.CanDomain(ctx, Principal{User: p.User}, p.DomainID, "dns:write")
		if e != nil || !allowed {
			return p, ErrForbidden
		}
	}
	return p, nil
}

func (s *Store) Token(ctx context.Context, token string) (Principal, error) {
	var p Principal
	var scopes []byte
	p.Token = true
	p.TokenHash = cryptobox.Hash(token)
	err := s.DB.QueryRowContext(ctx, "SELECT user_id,scopes FROM api_tokens WHERE token_hash=? AND expires_at>UTC_TIMESTAMP(6)", cryptobox.Hash(token)).Scan(&p.User.ID, &scopes)
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(scopes, &p.Scopes); err != nil {
		return p, err
	}
	p.User, err = s.User(ctx, p.User.ID)
	if err != nil {
		return p, err
	}
	if !p.User.Enabled {
		return p, ErrForbidden
	}
	_, err = s.DB.ExecContext(ctx, "UPDATE api_tokens SET last_used_at=UTC_TIMESTAMP(6) WHERE token_hash=?", cryptobox.Hash(token))
	return p, err
}

func (s *Store) CanDomain(ctx context.Context, p Principal, domain, action string) (bool, error) {
	if p.DomainID != "" {
		return p.DomainID == domain && (action == "dns:read" || action == "dns:write"), nil
	}
	if !p.AllowsScope(action) {
		return false, nil
	}
	if p.Admin() {
		return true, nil
	}
	var permissions []byte
	err := s.DB.QueryRowContext(ctx, "SELECT permissions FROM domain_grants WHERE user_id=? AND domain_id=?", p.User.ID, domain).Scan(&permissions)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var grants []string
	if err = json.Unmarshal(permissions, &grants); err != nil {
		return false, err
	}
	for _, grant := range grants {
		if grant == action || grant == "*" {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) LoginLimited(ctx context.Context, key string) (bool, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, "SELECT failures FROM login_attempts WHERE attempt_key=? AND expires_at>UTC_TIMESTAMP(6)", key).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return count >= 5, err
}

func (s *Store) LoginFailure(ctx context.Context, key string) error {
	_, err := s.DB.ExecContext(ctx, "INSERT INTO login_attempts (attempt_key,failures,expires_at) VALUES (?,1,DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 15 MINUTE)) ON DUPLICATE KEY UPDATE failures=IF(expires_at<UTC_TIMESTAMP(6),1,failures+1),expires_at=IF(expires_at<UTC_TIMESTAMP(6),DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 15 MINUTE),expires_at)", key)
	return err
}

func (s *Store) LoginSuccess(ctx context.Context, key string) error {
	_, err := s.DB.ExecContext(ctx, "DELETE FROM login_attempts WHERE attempt_key=?", key)
	return err
}
