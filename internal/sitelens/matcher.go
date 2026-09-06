package sitelens

// Matcher 指纹匹配器：加载精编指纹并预编译，供引擎跨页复用。
type Matcher struct {
	techs []*compiledTech
}

// LoadMatcher 从 JSON 文件加载指纹规则（data/go/technologies.json）。
func LoadMatcher(path string) (*Matcher, error) {
	techs, err := LoadTechnologies(path)
	if err != nil {
		return nil, err
	}
	return &Matcher{techs: techs}, nil
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
	raw := Match(m.techs, ev)
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
	for _, ct := range m.techs {
		if ct.tech.Name == name {
			return ct.tech
		}
	}
	return nil
}
