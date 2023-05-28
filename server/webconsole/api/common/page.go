package common

import (
	"context"
	"strconv"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PageReq struct {
	Page    int64             `form:"page,default=1" binding:"required,numeric,min=1"`
	Size    int64             `form:"size,default=10" binding:"required,numeric,min=1,max=5000"`
	Sort    map[string]string `form:"sort"`
	Filter  map[string][]any  `form:"filter"`
	Keyword map[string]any    `form:"keyword"`
}

type PageResp struct {
	Total int64                    `json:"total"`
	Items []map[string]interface{} `json:"items"`
}

func DBPageSearch(col *mongo.Collection, req *PageReq, filter bson.M) (*PageResp, error) {
	result := &PageResp{}
	// set up the options
	findOption := options.Find()
	// precheck for field
	if req.Sort != nil && len(req.Sort) == 1 {
		for k, v := range req.Sort {
			var order int
			switch v {
			case "ascend":
				order = 1
			case "descend":
				order = -1
			}
			if order != 0 {
				findOption.SetSort(bson.D{{Key: k, Value: order}})
			}
		}
	}
	findOption.SetSkip((req.Page - 1) * req.Size)
	findOption.SetLimit(req.Size)
	// Filter & keyword
	var f []bson.M
	if req.Filter != nil {
		for k, v := range req.Filter {
			if v == nil {
				continue
			}
			f = append(f, bson.M{k: bson.M{"$in": v}})
		}
	}
	if req.Keyword != nil {
		for k, v := range req.Keyword {
			var field string
			switch t := v.(type) {
			case string:
				field = t
			case int64:
				field = strconv.FormatInt(t, 10)
			case int:
				field = strconv.Itoa(t)
			default:
				continue
			}
			f = append(f, bson.M{
				k: primitive.Regex{
					Pattern: ".*" + field + ".*",
				},
			})
		}
	}
	combinedFilter := bson.D{{Key: "$and", Value: append([]bson.M{filter}, f...)}}
	// lookup the cursor
	cursor, err := col.Find(context.Background(), combinedFilter, findOption)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())
	// move the total after combined filter
	total, err := col.CountDocuments(context.Background(), combinedFilter)
	if err != nil {
		return nil, err
	}
	result.Total = total
	result.Items = make([]map[string]interface{}, 0)
	// get from cursor
	if err = cursor.All(context.TODO(), &result.Items); err != nil {
		return nil, err
	}
	return result, nil
}
