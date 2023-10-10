package mfastore

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

type Key struct {
	Username    string `json:"username"`
	Bytes       []byte `json:"bytes"`
	UserEnabled bool   `json:"account_enabled"`
	MFAEnabled  bool   `json:"mfa_enabled"`
}

type Store struct {
	Issuers map[string]map[string]Key `json:"issuers"`
}

func New() *Store {
	return &Store{
		Issuers: make(map[string]map[string]Key),
	}
}

func Load(filename string) (*Store, error) {
	store := New()
	data, err := os.ReadFile(filename)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		return store, nil
	}
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) GetKey(issuerName, username string) (*Key, error) {
	issuer, found := s.Issuers[issuerName]
	if !found {
		return nil, fmt.Errorf("issuer '%s' not found", issuerName)
	}
	key, found := issuer[username]
	if !found {
		return nil, fmt.Errorf("key not found for user '%s' under issuer '%s'", username, issuerName)
	}
	return &key, nil
}

func (s *Store) SetKey(issuerName string, key *Key) error {
	if _, found := s.Issuers[issuerName]; !found {
		log.Printf("Creating new issuer '%s'", issuerName)
		s.Issuers[issuerName] = make(map[string]Key)
	}
	if _, found := s.Issuers[issuerName][key.Username]; !found {
		log.Printf("Overriding key existing e-mail '%s' under issuer '%s'", key.Username, issuerName)
	}
	s.Issuers[issuerName][key.Username] = *key
	return nil
}

func (s *Store) Save(filename string) error {
	if s == nil {
		return fmt.Errorf("cannot save null store")
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}
