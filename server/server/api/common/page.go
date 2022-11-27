package common

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PageReq struct {
	Page       int64  `form:"page,default=1" binding:"required,numeric,min=1"`
	Size       int64  `form:"size,default=10" binding:"required,numeric,min=1,max=5000"`
	OrderKey   string `form:"order_key"`
	OrderValue int    `form:"order_value"`
}

type PageResp struct {
	Total int64                    `json:"total"`
	Items []map[string]interface{} `json:"items"`
}

func DBPageSearch(col *mongo.Collection, req *PageReq, searchFilter interface{}) (*PageResp, error) {
	result := &PageResp{}
	total, err := col.CountDocuments(context.Background(), searchFilter)
	if err != nil {
		// TODO log
		return nil, err
	}
	result.Total = total
	// set up the options
	findOption := options.Find()
	// precheck for field
	if req.OrderKey != "" || req.OrderValue != 0 {
		if req.OrderValue != 1 && req.OrderValue != -1 {
			err = errors.New("order value error")
			return nil, err
		}
		findOption.SetSort(bson.D{{Key: req.OrderKey, Value: req.OrderValue}})
	}
	findOption.SetSkip((req.Page - 1) * req.Size)
	findOption.SetLimit(req.Size)
	// lookup the cursor
	cursor, err := col.Find(context.Background(), searchFilter, findOption)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())
	result.Items = make([]map[string]interface{}, 0)
	// get from cursor
	if err = cursor.All(context.TODO(), &result.Items); err != nil {
		return nil, err
	}
	return result, nil
}

// DBAggPageSearch is for inline array search for now
// func DBAggPageSearch(col *mongo.Collection, req *PageReq, pipeline []interface{}) (*PageResp, error) {
// 	if req.OrderKey != "" {
// 		pipeline = append(pipeline, bson.D{
// 			{
// 				Key: "$sort", Value: bson.D{
// 					{
// 						Key:   req.OrderKey,
// 						Value: req.OrderValue,
// 					},
// 				},
// 			},
// 		})
// 	}
// 	pipeline = append(pipeline, bson.D{{Key: "$skip", Value: (req.Page - 1) * req.Size}},
// 		bson.D{{Key: "$limit", Value: req.Size}})
// 	cur, err := col.Aggregate(
// 		context.TODO(),
// 		pipeline,
// 	)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return
// }
