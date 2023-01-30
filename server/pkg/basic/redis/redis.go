package redis

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-redis/redis/v8"
)

var Inst redis.UniversalClient

type RedisMode int

const (
	RedisModeCluster RedisMode = iota
	RedisModeSentinel
	RedisModeSingle
)

func NewRedisClient(addrs []string, masterName, password string, mode RedisMode) error {
	if len(addrs) == 0 {
		return errors.New("addrs is required")
	}
	switch mode {
	// Sentinel
	case RedisModeSentinel:
		opts := &redis.FailoverOptions{
			SentinelAddrs: addrs,
			MasterName:    masterName,
			Password:      password,
		}
		client := redis.NewFailoverClient(opts)
		_, err := client.Ping(context.Background()).Result()
		if err != nil {
			return err
		}
		Inst = client
		return nil
	// Cluster
	case RedisModeCluster:
		opts := &redis.ClusterOptions{
			Addrs:    addrs,
			Password: password,
		}
		client := redis.NewClusterClient(opts)
		_, err := client.Ping(context.Background()).Result()
		if err != nil {
			return err
		}
		Inst = client
		return nil
	case RedisModeSingle:
		opts := &redis.Options{
			Addr:     addrs[0],
			Password: password,
		}
		client := redis.NewClient(opts)
		_, err := client.Ping(context.Background()).Result()
		if err != nil {
			return err
		}
		Inst = client
		return nil
	default:
		return fmt.Errorf("redis mode %d is not valid", mode)
	}
}
