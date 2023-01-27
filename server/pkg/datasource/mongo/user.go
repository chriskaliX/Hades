package mongo

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
