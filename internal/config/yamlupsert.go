// YAML 读改写：设置页保存用。基于 yaml.v3 Node 保留注释与未纳管键，
// 只更新指定段落里的指定键（键不存在则追加）。
package config

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// UpsertYAMLSections 在 data（YAML 文档）中按段更新键值。
// updates: 段名 → {键: 值}。段或键不存在则创建。返回重新序列化的文档。
func UpsertYAMLSections(data []byte, updates map[string]map[string]any) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if len(root.Content) == 0 {
		return nil, fmt.Errorf("空文档")
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("顶层不是映射")
	}
	for section, kvs := range updates {
		secNode := mappingChild(doc, section)
		if secNode == nil {
			secNode = appendMappingChild(doc, section)
		}
		if secNode.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("段 %s 不是映射", section)
		}
		for k, v := range kvs {
			setMappingValue(secNode, k, v)
		}
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	enc.Close()
	return out.Bytes(), nil
}

// mappingChild 在映射节点里查找键对应的值节点。
func mappingChild(mapNode *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		if mapNode.Content[i].Value == key {
			return mapNode.Content[i+1]
		}
	}
	return nil
}

// appendMappingChild 追加键（空值占位映射）。
func appendMappingChild(mapNode *yaml.Node, key string) *yaml.Node {
	kn := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	vn := &yaml.Node{Kind: yaml.MappingNode}
	mapNode.Content = append(mapNode.Content, kn, vn)
	return vn
}

// setMappingValue 设置映射里键的标量值（不存在则追加）。
// 值节点按 Go 类型打 tag：bool→!!bool、数值→!!int，字符串→!!str——
// 否则 yml 写出全为字符串，重新解析 int 字段会失败并整体回退默认。
func setMappingValue(mapNode *yaml.Node, key string, val any) {
	vn := &yaml.Node{Kind: yaml.ScalarNode}
	switch v := val.(type) {
	case bool:
		vn.Tag = "!!bool"
		vn.Value = fmt.Sprint(v)
	case int:
		vn.Tag = "!!int"
		vn.Value = fmt.Sprint(v)
	case int64:
		vn.Tag = "!!int"
		vn.Value = fmt.Sprint(v)
	case float64:
		vn.Tag = "!!float"
		vn.Value = fmt.Sprint(v)
	default:
		vn.Tag = "!!str"
		vn.Value = fmt.Sprint(v)
	}
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		if mapNode.Content[i].Value == key {
			mapNode.Content[i+1] = vn
			return
		}
	}
	kn := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	mapNode.Content = append(mapNode.Content, kn, vn)
}
