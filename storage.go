package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Storage interface {
	CreateAccount(*Account) error
	UpdateAccount(*Account) error
	DeleteAccount(id int) error
    GetAllAccounts() ([]*Account, error)
	GetAccountByID(int) (*Account, error)
    GetHashedPassword(string) (*Account, error)
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	connStr := "user=postgres dbname=gobank password=ironman sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgresStore{
		db: db,
	}, nil
}

func (s *PostgresStore) Init() error {
	return s.CreateAccountTable()
}

func (s *PostgresStore) CreateAccountTable() error {
	query := `CREATE TABLE IF NOT EXISTS accounts (
        id SERIAL PRIMARY KEY,
        first_name VARCHAR(50),
        last_name VARCHAR(50),
        email VARCHAR(50),
        passhash VARCHAR(300),
        number SERIAL, 
        balance INT,
        created_at TIMESTAMP
    )`
	_, err := s.db.Exec(query)
    if err != nil {
        return err
    }
    query = `ALTER TABLE accounts ADD UNIQUE (email)`;
    _, err = s.db.Exec(query)
	return err
}

func (s *PostgresStore) CreateAccount(acc *Account) error {
    query := `INSERT INTO accounts
    (first_name, last_name, email, passhash, balance, number, created_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.db.Query(
        query, 
        acc.FirstName,
        acc.LastName,
        acc.Email,
        acc.EncryptedPassword,
        acc.Balance,
        acc.Number,
        acc.CreatedAt,
    )
    if err != nil {
        return err
    }
	return nil
}

func (s *PostgresStore) GetAllAccounts() ([]*Account, error) {
    query := `SELECT * FROM accounts`
    rows, err := s.db.Query(query)
    if err != nil {
        return nil, err
    }
    accounts := []*Account{}
    for rows.Next() {
        account, err := scanIntoAccount(rows)
        if err != nil {
            return nil, err
        }
        accounts = append(accounts, account)
    }

    return accounts, nil
}

func (s *PostgresStore) GetHashedPassword(email string) (*Account, error) {
    query := `SELECT id, passhash FROM accounts WHERE email=$1`
    rows, err := s.db.Query(query, email)
    if err != nil {
        return nil, err
    }
    account := Account{}
    for rows.Next() {
        if err := rows.Scan(&account.ID, &account.EncryptedPassword); err != nil {
            return nil, err
        }
        return &account, nil
    }

    return nil, fmt.Errorf("account [email: %s] not found", email)
}

func (s *PostgresStore) GetAccountByID(id int) (*Account, error) {
    query := `SELECT * FROM accounts WHERE id=$1`
    rows, err := s.db.Query(query, id)
    if err != nil {
        return nil, err
    }
    for rows.Next() {
        return scanIntoAccount(rows)
    } 
	return nil, fmt.Errorf("account %d not found", id)
}

func (s *PostgresStore) UpdateAccount(*Account) error {
	return nil
}

func (s *PostgresStore) DeleteAccount(id int) error {
    query := `DELETE FROM accounts WHERE id = $1`
    _, err := s.db.Query(query, id)
	return err
}

func scanIntoAccount(rows *sql.Rows) (*Account, error) {
    acc := Account{}
    if err := rows.Scan(
        &acc.ID, 
        &acc.FirstName, 
        &acc.LastName, 
        &acc.Email,
        &acc.EncryptedPassword,
        &acc.Number, 
        &acc.Balance, 
        &acc.CreatedAt,
    ); err != nil {
        return nil, err
    }
    return &acc, nil
}
