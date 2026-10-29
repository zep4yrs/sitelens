package sitelens

// Matcher 指纹匹配器：加载精编指纹并预编译，供引擎跨页复用。
type Matcher struct {
	techs  []*compiledTech
	byName map[string]*compiledTech // 技术名 → 指纹（命中后补元数据 O(1)）
	litPS  *litPrescreen
}

// LoadMatcher 从 JSON 文件加载指纹规则（data/go/technologies.json）。
func LoadMatcher(path string) (*Matcher, error) {
	techs, err := LoadTechnologies(path)
	if err != nil {
		return nil, err
	}
	m := &Matcher{techs: techs, byName: make(map[string]*compiledTech, len(techs))}
	for _, ct := range techs {
		// 同名指纹只保留首条：与原线性查找「返回第一个同名」的语义一致
		if _, ok := m.byName[ct.tech.Name]; !ok {
			m.byName[ct.tech.Name] = ct
		}
	}
	m.litPS = buildLitPrescreen(techs)
	return m, nil
}

// Count 已加载的指纹条数。
func (m *Matcher) Count() int { return len(m.techs) }

// MatchHit 引擎侧的指纹命中（补全技术元数据）。
type MatchHit struct {
	Name     string   `json:"name"`
	Cats     []string `json:"cats"`
	Conf     int      `json:"conf"`
	Website  string   `json:"website"`
	Evidence string   `json:"evidence"`
	Version  string   `json:"version"`
}

// Match 对一份证据应用全部指纹。
func (m *Matcher) Match(ev *Evidence) []MatchHit {
	raw := MatchPrescreen(m.techs, ev, m.litPS)
	out := make([]MatchHit, 0, len(raw))
	for _, h := range raw {
		mh := MatchHit{Name: h.Name, Cats: h.Cats, Conf: h.Conf, Evidence: h.Evidence, Version: h.Version}
		if h := m.find(h.Name); h != nil {
			mh.Website = h.Website
			if len(mh.Cats) == 0 {
				mh.Cats = []string{}
			}
		}
		out = append(out, mh)
	}
	return out
}

func (m *Matcher) find(name string) *Technology {
	// byName 为 nil（零值 Matcher / 空指纹库）时读 map 返回零值，行为不变。
	if ct := m.byName[name]; ct != nil {
		return ct.tech
	}
	return nil
}
