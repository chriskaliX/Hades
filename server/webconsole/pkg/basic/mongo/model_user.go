package mongo

import (
	"context"
	"fmt"
	"hboat/pkg/basic/utils"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

type RoleId int

const (
	RoleAdmin RoleId = iota
	RoleReadWrite
	RoleRead
)

type StatusId int

const (
	Normal StatusId = iota
	ForbidPassword
	ForbidSSO
	ForbidAll
)

type User struct {
	Username           string   `json:"username" bson:"username"`
	Password           string   `json:"password" bson:"password"`
	Salt               string   `json:"salt" bson:"salt"`
	AvatarUrl          string   `json:"avatar_url" bson:"avatar_url"`
	Role               RoleId   `json:"role" bson:"role"`
	PasswordUpdateTime int64    `json:"password_update_time" bson:"password_update_time"`
	Status             StatusId `json:"status" bson:"status"`
}

// createUser with the hashed password
func CreateUser(username string, password string, Role RoleId) error {
	salt := utils.RandStringRunes(16)
	hashedPasswd, err := bcrypt.GenerateFromPassword([]byte(password+salt), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	// check if already exists
	res := MongoProxyImpl.UserC.FindOne(
		context.Background(),
		bson.M{"username": username},
	)
	if res.Err() == nil {
		return fmt.Errorf("user %s already exists", username)
	}
	// start to new user
	user := User{
		Username:           username,
		Password:           string(hashedPasswd),
		Salt:               salt,
		AvatarUrl:          "",
		Role:               Role,
		PasswordUpdateTime: time.Now().Unix(),
		Status:             Normal,
	}
	if _, err = MongoProxyImpl.UserC.InsertOne(
		context.Background(),
		user,
	); err != nil {
		return err
	}
	return nil
}

// CheckPassword by username and password
func CheckPassword(username string, password string) error {
	// check if user exists
	res := MongoProxyImpl.UserC.FindOne(
		context.Background(),
		bson.M{"username": username},
	)
	if res.Err() != nil {
		return res.Err()
	}
	// select and check
	var user User
	if err := res.Decode(&user); err != nil {
		return err
	}
	// check user password
	return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password+user.Salt))
}

// Change username
func ChangePassword(username string, password string) error {
	// check if user exists
	res := MongoProxyImpl.UserC.FindOne(
		context.Background(),
		bson.M{"username": username},
	)
	if res.Err() != nil {
		return res.Err()
	}
	// select and check
	var user User
	passwd, err := bcrypt.GenerateFromPassword([]byte(password+user.Salt), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(passwd)
	user.PasswordUpdateTime = time.Now().Unix()
	_, err = MongoProxyImpl.UserC.UpdateOne(
		context.Background(),
		bson.M{"username": username},
		bson.M{"$set": bson.M{"password": user.Password, "password_update_time": user.PasswordUpdateTime}},
	)
	return err
}
