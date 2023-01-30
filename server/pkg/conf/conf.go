package conf

// MongoDB related
const MongoURI = "mongodb://localhost:27017"
const MAgentStatusCollection = "agentstatus"

// redis related
const RedisMode = 2 // single
var RedisAddrs = []string{"127.0.0.1:6379"}

const RedisMasterName = ""
const RedisPassword = ""

// Agent related
const AgentHBSec = 300

// User related
const UserSessionLifetimeMin = 120

// Token key
const TokenKey = "token"
const IsAuth = true
