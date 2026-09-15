package store

import "encoding/json"

// 组名/描述是 JSONB 列：包一层小助手，避免每个调用点都写一遍错误处理。
func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

func jsonUnmarshal(raw []byte, v any) error { return json.Unmarshal(raw, v) }
