package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type Account struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Provider  string            `json:"provider"`
	Remark    string            `json:"remark"`
	Status    string            `json:"status"`
	LastError string            `json:"last_error"`
	CreatedAt time.Time         `json:"created_at"`
	Config    map[string]string `json:"-"`
}

func (s *Store) Accounts(ctx context.Context) ([]Account, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id,name,provider,remark,status,last_error,created_at FROM provider_accounts ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Account{}
	for rows.Next() {
		var a Account
		if err = rows.Scan(&a.ID, &a.Name, &a.Provider, &a.Remark, &a.Status, &a.LastError, &a.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

func (s *Store) Account(ctx context.Context, id string) (Account, error) {
	var a Account
	var ciphertext string
	err := s.DB.QueryRowContext(ctx, "SELECT id,name,provider,remark,status,last_error,created_at,config_ciphertext FROM provider_accounts WHERE id=?", id).Scan(&a.ID, &a.Name, &a.Provider, &a.Remark, &a.Status, &a.LastError, &a.CreatedAt, &ciphertext)
	if err != nil {
		return a, err
	}
	err = s.Decrypt("account:"+a.ID, ciphertext, &a.Config)
	return a, err
}

func (s *Store) SaveAccount(ctx context.Context, a Account, create bool) (Account, error) {
	var err error
	if create {
		a.ID, err = ID()
		if err != nil {
			return a, err
		}
	}
	enc, err := s.Encrypt("account:"+a.ID, a.Config)
	if err != nil {
		return a, err
	}
	if create {
		_, err = s.DB.ExecContext(ctx, "INSERT INTO provider_accounts (id,name,provider,config_ciphertext,remark,status,created_at,updated_at) VALUES (?,?,?,?,?,'unverified',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))", a.ID, a.Name, a.Provider, enc, a.Remark)
	} else {
		var result sql.Result
		result, err = s.DB.ExecContext(ctx, "UPDATE provider_accounts SET name=?,config_ciphertext=?,remark=?,status='unverified',last_error='',updated_at=UTC_TIMESTAMP(6) WHERE id=?", a.Name, enc, a.Remark, a.ID)
		if err == nil {
			n, _ := result.RowsAffected()
			if n == 0 {
				return a, sql.ErrNoRows
			}
		}
	}
	if err != nil {
		return a, err
	}
	return s.Account(ctx, a.ID)
}

type Domain struct {
	Permissions       []string  `json:"permissions,omitempty"`
	ID                string    `json:"id"`
	AccountID         string    `json:"account_id"`
	ProviderDomainID  string    `json:"provider_domain_id"`
	Name              string    `json:"name"`
	ASCIIName         string    `json:"ascii_name"`
	Provider          string    `json:"provider"`
	Category          string    `json:"category"`
	Remark            string    `json:"remark"`
	QuickloginEnabled bool      `json:"quicklogin_enabled"`
	Hidden            bool      `json:"hidden"`
	CreatedAt         time.Time `json:"created_at"`
}

const domainColumns = "d.id,d.account_id,d.provider_domain_id,d.name,d.ascii_name,a.provider,d.category,d.remark,d.quicklogin_enabled,d.hidden,d.created_at"

func scanDomain(row interface{ Scan(...any) error }) (Domain, error) {
	var d Domain
	err := row.Scan(&d.ID, &d.AccountID, &d.ProviderDomainID, &d.Name, &d.ASCIIName, &d.Provider, &d.Category, &d.Remark, &d.QuickloginEnabled, &d.Hidden, &d.CreatedAt)
	return d, err
}
func (s *Store) Domain(ctx context.Context, id string) (Domain, error) {
	return scanDomain(s.DB.QueryRowContext(ctx, "SELECT "+domainColumns+" FROM domains d JOIN provider_accounts a ON a.id=d.account_id WHERE d.id=?", id))
}
func (s *Store) Domains(ctx context.Context, p Principal) ([]Domain, error) {
	query := "SELECT " + domainColumns + " FROM domains d JOIN provider_accounts a ON a.id=d.account_id"
	var args []any
	if p.DomainID != "" {
		query += " WHERE d.id=?"
		args = append(args, p.DomainID)
	} else if !p.Admin() {
		query += " WHERE EXISTS (SELECT 1 FROM domain_grants g WHERE g.user_id=? AND g.domain_id=d.id)"
		args = append(args, p.User.ID)
	}
	query += " ORDER BY d.name"
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Domain{}
	for rows.Next() {
		d, e := scanDomain(rows)
		if e != nil {
			return nil, e
		}
		allowed, e := s.CanDomain(ctx, p, d.ID, "dns:read")
		if e != nil {
			return nil, e
		}
		if allowed {
			list = append(list, d)
		}
	}
	return list, rows.Err()
}
func (s *Store) AddDomain(ctx context.Context, d Domain) (Domain, error) {
	id, err := ID()
	if err != nil {
		return d, err
	}
	d.ID = id
	_, err = s.DB.ExecContext(ctx, "INSERT INTO domains (id,account_id,provider_domain_id,name,ascii_name,category,remark,created_at,updated_at) VALUES (?,?,?,?,?,?,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))", d.ID, d.AccountID, d.ProviderDomainID, d.Name, d.ASCIIName, d.Category, d.Remark)
	if err != nil {
		return d, err
	}
	return s.Domain(ctx, d.ID)
}

type Object struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	Name          string          `json:"name"`
	DomainID      string          `json:"domain_id,omitempty"`
	OwnerID       string          `json:"owner_id"`
	Data          json.RawMessage `json:"data"`
	Version       int64           `json:"version"`
	ConfigVersion int64           `json:"-"`
	Active        bool            `json:"active"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

func (s *Store) Object(ctx context.Context, id string) (Object, error) {
	var o Object
	var domain sql.NullString
	var enc string
	err := s.DB.QueryRowContext(ctx, "SELECT id,kind,name,domain_id,owner_id,data_ciphertext,version,active,created_at,updated_at,config_version FROM objects WHERE id=?", id).Scan(&o.ID, &o.Kind, &o.Name, &domain, &o.OwnerID, &enc, &o.Version, &o.Active, &o.CreatedAt, &o.UpdatedAt, &o.ConfigVersion)
	if err != nil {
		return o, err
	}
	o.DomainID = domain.String
	plain, err := s.Box.Open("object:"+o.ID, enc)
	o.Data = plain
	return o, err
}

func (s *Store) Objects(ctx context.Context, kind string) ([]Object, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id FROM objects WHERE kind=? ORDER BY updated_at DESC", kind)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	list := []Object{}
	for _, id := range ids {
		o, e := s.Object(ctx, id)
		if e != nil {
			return nil, e
		}
		list = append(list, o)
	}
	return list, nil
}

func (s *Store) SaveObject(ctx context.Context, o Object, create bool) (Object, error) {
	var err error
	if create {
		o.ID, err = ID()
		if err != nil {
			return o, err
		}
	}
	if !json.Valid(o.Data) {
		return o, errors.New("invalid object JSON")
	}
	if !create {
		if _, err = s.Object(ctx, o.ID); err != nil {
			return o, err
		}
	}
	var data map[string]json.RawMessage
	if json.Unmarshal(o.Data, &data) != nil {
		return o, errors.New("object must be a JSON object")
	}
	o.Data, err = json.Marshal(data)
	if err != nil {
		return o, err
	}
	enc, err := s.Box.Seal("object:"+o.ID, o.Data)
	if err != nil {
		return o, err
	}
	if create {
		_, err = s.DB.ExecContext(ctx, "INSERT INTO objects (id,kind,name,domain_id,owner_id,data_ciphertext,version,active,created_at,updated_at) VALUES (?,?,?,?,?,?,1,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))", o.ID, o.Kind, o.Name, nullString(o.DomainID), o.OwnerID, enc, o.Active)
	} else {
		result, e := s.DB.ExecContext(ctx, "UPDATE objects SET name=?,data_ciphertext=?,active=?,version=version+1,config_version=config_version+1,updated_at=UTC_TIMESTAMP(6) WHERE id=? AND version=?", o.Name, enc, o.Active, o.ID, o.Version)
		err = e
		if err == nil {
			count, _ := result.RowsAffected()
			if count == 0 {
				return o, ErrConflict
			}
		}
	}
	if err != nil {
		return o, err
	}
	return s.Object(ctx, o.ID)
}
