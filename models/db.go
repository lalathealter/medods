package models

import (
	"context"
	"fmt"
	"log"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const MEDODS_DB_NAME = "medods"
const REFRESH_TOKENS_COLLECTION = "refreshes"


type DBI interface {
	FindIfContains(string) bool
	InsertRefreshTokenHash(string, []byte) error
	GetRefreshTokenHash(string) ([]byte, error)
	DeleteRefreshTokenHash(string) error
}

type WrapperDB struct {
	Client *mongo.Client
}


func InitWrapperDB(connURL string) *WrapperDB {
	if connURL == "" {
		log.Fatal(ErrEmptyConnectionString)
	}

	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(connURL).SetServerAPIOptions(serverAPI)
	client, err := mongo.Connect(context.TODO(), opts)
	if err != nil {
		log.Panic(err)
	}

	if err := client.Database("admin").RunCommand(context.TODO(), bson.D{{"ping", 1}}).Err(); err != nil {
		log.Panic(err)
	}
	fmt.Println("Successfully connected to mongodb")

	wrap := &WrapperDB{client}

	return wrap
}

func (wdb *WrapperDB) getRefreshesColl() *mongo.Collection {
	return wdb.Client.Database(MEDODS_DB_NAME).Collection(REFRESH_TOKENS_COLLECTION)
}

type RefreshTokenModel struct {
	UNID       string
	BcryptHash []byte
}

func (wdb *WrapperDB) FindIfContains(tokenUNID string) bool {
	coll := wdb.getRefreshesColl()
	refToken := RefreshTokenModel{}
	filter := bson.D{{"unid", tokenUNID}}
	err := coll.FindOne(context.TODO(), filter).Decode(&refToken)
	return err == nil
}

func (wdb *WrapperDB) InsertRefreshTokenHash(UNID string, bcryptHash []byte) error {
	coll := wdb.getRefreshesColl()
	newTokenHash := RefreshTokenModel{UNID, bcryptHash}
	_, err := coll.InsertOne(context.TODO(), newTokenHash)
	return err
}

func (wdb *WrapperDB) DeleteRefreshTokenHash(unid string) error {
	coll := wdb.getRefreshesColl()
	filter := bson.D{{"unid", unid}}
	_, err := coll.DeleteOne(context.TODO(), filter)
	return err
}

func (wdb *WrapperDB) GetRefreshTokenHash(unid string) ([]byte, error) {
	coll := wdb.getRefreshesColl()
	tokenModel := RefreshTokenModel{}
	filter := bson.D{{"unid", unid}}
	err := coll.FindOne(context.TODO(), filter).Decode(&tokenModel)

	return tokenModel.BcryptHash, err
}
