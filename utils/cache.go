package utils

import (
	"time"
	"vls-api/models"
)

type Cache struct {
	data map[string]CacheItem
}

type CacheItem struct {
	Value      models.ScanResults
	Expiration int64
}

func (c *Cache) Get(key string) (*models.ScanResults, bool) {
	item, ok := c.data[key]
	if !ok {
		return nil, false
	}
	if time.Now().UnixNano() > item.Expiration {
		delete(c.data, key)
		return nil, false
	}

	return &item.Value, true
}

func (c *Cache) Set(key string, value models.ScanResults, expiration time.Duration) {
	if c.data == nil {
		c.data = make(map[string]CacheItem)
	}

	c.data[key] = CacheItem{
		Value:      value,
		Expiration: time.Now().Add(expiration).UnixNano(),
	}
}
