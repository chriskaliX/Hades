package pkg

import (
	"context"
	"fmt"
	"hboat/pkg/datasource"
	"hboat/pkg/internal/user"
	"hboat/pkg/internal/utils"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func UserInit() error {
	// init the admin
	res := datasource.UserC.FindOne(context.Background(), bson.M{"username": "admin"})
	if res.Err() == mongo.ErrNoDocuments {
		passwd := utils.RandStringRunes(6)
		err := user.CreateUser("admin", passwd, 0)
		if err != nil {
			return err
		}
		fmt.Println(passwd)
	}
	return nil
}
