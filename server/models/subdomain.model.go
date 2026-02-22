package models

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Config struct {
	DB struct {
		URI      string `json:"uri"`
		Database string `json:"database"`
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

func ConnectDB() (*mongo.Database, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}

	clientOptions := options.Client().ApplyURI(cfg.DB.URI)

	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		return nil, err
	}

	err = client.Ping(context.Background(), nil)
	if err != nil {
		return nil, err
	}

	return client.Database(cfg.DB.Database), nil
}

type SubDomain struct {
	ID              interface{} `bson:"_id,omitempty" json:"id"`
	Subdomain       string      `bson:"subdomain" json:"subdomain"`
	TokenHash       string      `bson:"tokenHash" json:"tokenHash"`
	Status          bool        `bson:"status" json:"status"`
	IsConnected     bool        `bson:"isConnected" json:"isConnected"`
	IsBanned        bool        `bson:"isBanned" json:"isBanned"`
	IP              string      `bson:"ipAddress,omitempty" json:"ipAddress,omitempty"`
	UserAgent       string      `bson:"userAgent,omitempty" json:"userAgent,omitempty"`
	FailedAuthCount int         `bson:"failedAuthCount,omitempty" json:"failedAuthCount,omitempty"`
}

type SubDomainModel struct {
	Collection *mongo.Collection
}

func NewSubDomainModel() (*SubDomainModel, error) {
	db, err := ConnectDB()
	if err != nil {
		return nil, err
	}

	return &SubDomainModel{
		Collection: db.Collection("subdomains")}, nil
}

func (m *SubDomainModel) GetBySubdomain(subdomain string) (*SubDomain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var sd SubDomain
	err := m.Collection.FindOne(ctx, bson.M{"subdomain": subdomain}).Decode(&sd)
	if err != nil {
			log.Println(err)
		return nil, err
	}
	log.Println(&sd,subdomain)
	return &sd, nil
}

func (m *SubDomainModel) UpdateByKey(subdomain string, key string, value interface{}) error {

	allowed := map[string]bool{
		"status":       true,
		"isConnected": true,
		"isBanned":    true,
	}

	if !allowed[key] {
		return fmt.Errorf("invalid update key: %s", key)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Collection.UpdateOne(
		ctx,
		bson.M{"subdomain": subdomain},
		bson.M{"$set": bson.M{key: value}},
	)

	return err
}

func (m *SubDomainModel) MarkConnected(subdomain string, ip string, userAgent string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Collection.UpdateOne(
		ctx,
		bson.M{"subdomain": subdomain},
		bson.M{
			"$set": bson.M{
				"isConnected":      1,
				"ip_address":        ip,
				"user_agent":        userAgent,
				"failedAuthCount": 0,
			},
		},
	)

	return err
}

func (m *SubDomainModel) MarkDisconnected(subdomain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Collection.UpdateOne(
		ctx,
		bson.M{"subdomain": subdomain},
		bson.M{
			"$set": bson.M{
				"isConnected":         0,
			},
		},
	)

	return err
}

func (m *SubDomainModel) UpdateFailedAuth(subdomain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Collection.UpdateOne(
		ctx,
		bson.M{"subdomain": subdomain},
		bson.M{
			"$inc": bson.M{"failedAuthCount": 1},
		},
	)

	return err
}
