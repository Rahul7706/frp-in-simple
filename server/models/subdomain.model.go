package models

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

type Config struct {
	DB struct {
		User     string `json:"user"`
		Password string `json:"password"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Name     string `json:"name"`
	} `json:"db"`
}

func LoadConfig() (*Config, error) {
	file, err := os.ReadFile("config.json")
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = json.Unmarshal(file, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func ConnectDB() (*sql.DB, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
		cfg.DB.User,
		cfg.DB.Password,
		cfg.DB.Host,
		cfg.DB.Port,
		cfg.DB.Name,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	// test connection
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

type SubDomain struct {
	ID          int64  `json:"id"`
	Subdomain   string `json:"subdomain"`
	TokenHash   string `json:"token_hash"`
	Status      int    `json:"status"`
	IsConnected int    `json:"is_connected"`
	IsBanned    int    `json:"is_banned"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type SubDomainModel struct {
	DB *sql.DB
}

func NewSubDomainModel() (*SubDomainModel, error) {
	db, err := ConnectDB()
	if err != nil {
		return nil, err
	}

	return &SubDomainModel{DB: db}, nil
}

func (m *SubDomainModel) GetBySubdomain(subdomain string) (*SubDomain, error) {
	query := `SELECT id, subdomain, token_hash, status, is_connected, is_banned, created_at, updated_at
			  FROM sub_domain_list WHERE subdomain = ? LIMIT 1`

	var sd SubDomain
	err := m.DB.QueryRow(query, subdomain).Scan(
		&sd.ID,
		&sd.Subdomain,
		&sd.TokenHash,
		&sd.Status,
		&sd.IsConnected,
		&sd.IsBanned,
		&sd.CreatedAt,
		&sd.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &sd, nil
}



func (m *SubDomainModel) UpdateByKey(subdomain string, key string, value any) error {

	allowed := map[string]bool{
		"status":       true,
		"is_connected": true,
		"is_banned":    true,
		"token_hash":   true,
	}

	if !allowed[key] {
		return fmt.Errorf("invalid update key: %s", key)
	}

	query := fmt.Sprintf("UPDATE sub_domain_list SET %s = ? WHERE subdomain = ?", key)

	_, err := m.DB.Exec(query, value, subdomain)
	return err
}


func (m *SubDomainModel) MarkConnected(subdomain string, ip string, userAgent string) error {
	query := `
		UPDATE sub_domain_list
		SET 
			is_connected = 1,
			last_connected_at = NOW(),
			ip_address = ?,
			user_agent = ?,
			failed_auth_count = 0
		WHERE subdomain = ?
	`
	_, err := m.DB.Exec(query, ip, userAgent, subdomain)
	return err
}

func (m *SubDomainModel) MarkDisconnected(subdomain string) error {
	query := `
		UPDATE sub_domain_list
		SET 
			is_connected = 0,
			last_disconnected_at = NOW()
		WHERE subdomain = ?
	`
	_, err := m.DB.Exec(query, subdomain)
	return err
}

func (m *SubDomainModel) UpdateFailedAuth(subdomain string) error {
	query := `
		UPDATE sub_domain_list
		SET failed_auth_count = failed_auth_count + 1
		WHERE subdomain = ?
	`
	_, err := m.DB.Exec(query, subdomain)
	return err
}
