package store

import (
	"github.com/google/uuid"
	"github.com/lib/pq"
)

func newUUID() string { return uuid.NewString() }

func pqArray(v []string) interface{} { return pq.Array(v) }
