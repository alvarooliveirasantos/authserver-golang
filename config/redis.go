package config

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

type Cache interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
}

type RedisClient struct {
	Client *redis.Client
	Logger *logrus.Entry
}

func NewRedisClient(addr, password string, db int) *RedisClient {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	logger := logrus.WithFields(logrus.Fields{
		"component": "redis",
	})

	return &RedisClient{
		Client: client,
		Logger: logger,
	}
}

func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	err := r.Client.Set(ctx, key, value, expiration).Err()
	if err != nil {
		r.Logger.WithFields(logrus.Fields{
			"key":   key,
			"value": value,
		}).Error("Failed to set value in Redis", err)
		return err
	}
	r.Logger.Info("Value set in Redis", key)
	return nil
}

func (r *RedisClient) Get(ctx context.Context, key string) (string, error) {
	val, err := r.Client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			r.Logger.WithFields(logrus.Fields{
				"key": key,
			}).Warn("Key does not exist in Redis")
		} else {
			r.Logger.WithFields(logrus.Fields{
				"key": key,
			}).Error("Failed to get value from Redis")
		}
		return "", err
	}
	r.Logger.WithFields(logrus.Fields{
		"key":   key,
		"value": val,
	}).Info("Value retrieved from Redis")
	return val, nil
}
