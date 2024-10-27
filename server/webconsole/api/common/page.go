package common

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// PageReq represents pagination request parameters
type PageReq struct {
	Page    int64             `form:"page,default=1" binding:"required,numeric,min=1"`
	Size    int64             `form:"size,default=10" binding:"required,numeric,min=1,max=5000"`
	Sort    map[string]string `form:"sort"`
	Filter  map[string][]any  `form:"filter"`
	Keyword map[string]any    `form:"keyword"`
}

// PageResp represents the response structure for pagination
type PageResp struct {
	Total int64                    `json:"total"`
	Items []map[string]interface{} `json:"items"`
}

// DBPageSearch performs a paginated search on the given MongoDB collection
func DBPageSearch(ctx context.Context, col *mongo.Collection, req *PageReq, filter bson.M) (*PageResp, error) {
	result := &PageResp{}

	// Prepare find options with sorting and pagination
	findOptions := prepareFindOptions(req)

	// Build the combined filter
	combinedFilter := buildCombinedFilter(req, filter)

	// Perform the query
	cursor, err := col.Find(ctx, combinedFilter, findOptions)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	// Get total count of documents matching the combined filter
	total, err := col.CountDocuments(ctx, combinedFilter)
	if err != nil {
		return nil, err
	}

	result.Total = total

	// Retrieve items from cursor
	if err := cursor.All(ctx, &result.Items); err != nil {
		return nil, err
	}

	return result, nil
}

// prepareFindOptions sets up the sorting and pagination options for MongoDB query
func prepareFindOptions(req *PageReq) *options.FindOptions {
	findOptions := options.Find().
		SetSkip((req.Page - 1) * req.Size).
		SetLimit(req.Size)

	if len(req.Sort) == 1 {
		for field, order := range req.Sort {
			if orderValue := orderDirection(order); orderValue != 0 {
				findOptions.SetSort(bson.D{{Key: field, Value: orderValue}})
			}
		}
	}

	return findOptions
}

// orderDirection converts sort string to BSON order
func orderDirection(order string) int {
	switch order {
	case "ascend":
		return 1
	case "descend":
		return -1
	default:
		return 0
	}
}

// buildCombinedFilter constructs a combined filter for the MongoDB query
func buildCombinedFilter(req *PageReq, filter bson.M) bson.D {
	var filters []bson.M

	if req.Filter != nil {
		for key, values := range req.Filter {
			if len(values) > 0 {
				filters = append(filters, bson.M{key: bson.M{"$in": values}})
			}
		}
	}

    if req.Keyword != nil {
        for key, value := range req.Keyword {
            switch v := value.(type) {
            case string:
                filters = append(filters, bson.M{
                    key: primitive.Regex{
                        Pattern: "(?i).*" + v + ".*",
                    },
                })
            case float64, int, int32, int64:
                // 处理数字类型
                filters = append(filters, bson.M{
                    key: v,
                })
            default:
            }
        }
    }

	return bson.D{{Key: "$and", Value: append([]bson.M{filter}, filters...)}}
}

