package user

import (
	"context"
	"fmt"
	"hboat/pkg/datasource"
	"hboat/pkg/datasource/mongo"
	"hboat/pkg/internal/utils"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

// createUser with the hashed password
func CreateUser(username string, password string, Role mongo.RoleId) error {
	salt := utils.RandStringRunes(16)
	hashedPasswd, err := bcrypt.GenerateFromPassword([]byte(password+salt), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	// check if already exists
	res := datasource.UserC.FindOne(
		context.Background(),
		bson.M{"username": username},
	)
	if res.Err() == nil {
		return fmt.Errorf("user %s already exists", username)
	}
	// start to new user
	user := mongo.User{
		Username:           username,
		Password:           string(hashedPasswd),
		Salt:               salt,
		AvatarUrl:          "",
		Role:               Role,
		PasswordUpdateTime: time.Now().Unix(),
		Status:             mongo.Normal,
	}
	if _, err = datasource.UserC.InsertOne(
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
	res := datasource.UserC.FindOne(
		context.Background(),
		bson.M{"username": username},
	)
	if res.Err() != nil {
		return res.Err()
	}
	// select and check
	var user mongo.User
	if err := res.Decode(&user); err != nil {
		return err
	}
	// check user password
	return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password+user.Salt))
}

// Change username
func ChangePassword(username string, password string) error {
	// check if user exists
	res := datasource.UserC.FindOne(
		context.Background(),
		bson.M{"username": username},
	)
	if res.Err() != nil {
		return res.Err()
	}
	// select and check
	var user mongo.User
	passwd, err := bcrypt.GenerateFromPassword([]byte(password+user.Salt), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(passwd)
	user.PasswordUpdateTime = time.Now().Unix()
	_, err = datasource.UserC.UpdateOne(
		context.Background(),
		bson.M{"username": username},
		bson.M{"$set": bson.M{"password": user.Password, "password_update_time": user.PasswordUpdateTime}},
	)
	return err
}
