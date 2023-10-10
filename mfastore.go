package mfastore

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

type Key struct {
	Email string `json:"email"`
	Bytes []byte `json:"bytes"`
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

func (s *Store) GetKey(issuerName, email string) (*Key, error) {
	issuer, found := s.Issuers[issuerName]
	if !found {
		return nil, fmt.Errorf("issuer '%s' not found", issuer)
	}
	key, found := issuer[email]
	if !found {
		return nil, fmt.Errorf("key not found for user '%s' under issuer '%s'", email, issuer)
	}
	return &key, nil
}

func (s *Store) SetKey(issuerName, email string, keyBytes []byte) error {
	if _, found := s.Issuers[issuerName]; !found {
		log.Printf("Creating new issuer '%s'", issuerName)
		s.Issuers[issuerName] = make(map[string]Key)
	}
	if _, found := s.Issuers[issuerName][email]; !found {
		log.Printf("Overriding key existing e-mail '%s' under issuer '%s'", email, issuerName)
	}
	s.Issuers[issuerName][email] = Key{Email: email, Bytes: keyBytes}
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
