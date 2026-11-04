// 模板索引热路径：满模板池用户**每次扫描**都会调 Index（engine.nucleiSubset），
// 缓存命中时旧实现仍要（1）WalkDir 全池计数（2）读 + JSON 解码缓存文件
// ——14.4 万模板时这是每次扫描 ≈1.1s 的固定开销，比冷构建更常见。
//
// 本文件做两件事：
//
//  1. 目录 mtime 戳替代全量 walk：冷构建时把「所有目录的相对路径 →
//     mtime(unixnano)」写进缓存（cacheSchema v10）；热路径只对缓存里的
//     目录列表逐个 os.Stat（目录数通常 1-2k，实测比 14 万文件 walk 便宜
//     一个量级），任一戳变化/目录缺失 → 回落全量 WalkDir 重建。
//     依据：目录内任何文件增/删/改名都会更新父目录 mtime，因此「缓存里的
//     目录戳全等」⇒ 文件集合未变——与旧的 cached.Files == len(files) 计数
//     判定等价，且能发现「删一个又加一个」这类计数抵消的结构变化。
//     in-place 覆盖写（内容变化、目录结构不变）不更新父目录 mtime，新旧
//     判定都检测不到，是现状已知缺口，不在此修。
//
//  2. 进程内单条 memo：键 = cachePath + 缓存文件 mtime + size，命中直接复用
//     []Entry，免掉每次 18MB JSON 解码（外推 ~263ms）。缓存文件被重建或
//     外部改写时键自然失效；模板目录变化由目录戳校验负责，不依赖 memo 键。
//
// 语义边界：memo 命中时 Index 返回的是共享只读切片，调用方不得原地修改
// （现有调用方 engine.nucleiSubset / update_tplintel 均只读取或复制）。
package nuclei

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// dirStamp 目录戳：相对模板根目录的路径（slash 分隔，根目录为 "."）→
// 目录 mtime（unixnano）。目录增/删/改名都会改变父目录 mtime。
type dirStamp struct {
	Path  string `json:"p"`
	MTime int64  `json:"m"`
}

// walkTemplateFiles 全量 walk 模板目录：收集 yaml/yml 文件与所有目录戳。
// 文件集合与目录戳来自同一次 walk，保证缓存内容自洽。
//
// B2-11：walk 错误**必须上抛**。旧实现四处 `return nil` 静默吞错——某目录
// stat 失败时其文件不进索引、目录戳也不记录，此后该目录内容怎么变都检测不到
// （目录戳列表里没有它），残缺索引被当作有效缓存长期复用 → 模板静默缺失、
// 无任何告警。现在收集所有错误并 Join 返回，由 Index 决定失败语义。
func walkTemplateFiles(dir string) (files []string, stamps []dirStamp, err error) {
	var errs []error
	walkErr := filepath.WalkDir(dir, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			errs = append(errs, fmt.Errorf("walk %s: %w", p, werr))
			return nil // 继续走其余目录，最后统一上抛
		}
		if d.IsDir() {
			info, ierr := d.Info()
			if ierr != nil {
				errs = append(errs, fmt.Errorf("stat %s: %w", p, ierr))
				return nil
			}
			rel, rerr := filepath.Rel(dir, p)
			if rerr != nil {
				errs = append(errs, fmt.Errorf("rel %s: %w", p, rerr))
				return nil
			}
			stamps = append(stamps, dirStamp{Path: filepath.ToSlash(rel), MTime: info.ModTime().UnixNano()})
			return nil
		}
		if strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") {
			files = append(files, p)
		}
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr)
	}
	return files, stamps, errors.Join(errs...)
}

// dirStampsCurrent 校验缓存目录戳与当前目录树是否一致：stamps 全等（含根
// 目录）返回 true；任一目录缺失或 mtime 变化返回 false（调用方回落全量重建）。
//
// 目录 stat 是 syscall（本机实测 ~20µs/次，144k 池约 3k 个目录），并行摊薄；
// 目录数很少时顺序即可。
func dirStampsCurrent(root string, stamps []dirStamp) bool {
	if len(stamps) == 0 {
		return false // 无戳缓存（v9/空树）一律视为失效，走重建
	}
	workers := indexWorkers()
	if len(stamps) < 64 || workers <= 1 {
		for _, s := range stamps {
			if !dirStampCurrent(root, s) {
				return false
			}
		}
		return true
	}
	var next atomic.Int64
	var changed atomic.Bool
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(stamps) || changed.Load() {
					return
				}
				if !dirStampCurrent(root, stamps[i]) {
					changed.Store(true)
					return
				}
			}
		}()
	}
	wg.Wait()
	return !changed.Load()
}

// dirStampCurrent 单个目录戳是否仍然成立。
func dirStampCurrent(root string, s dirStamp) bool {
	p := root
	if s.Path != "." && s.Path != "" {
		p = filepath.Join(root, filepath.FromSlash(s.Path))
	}
	info, err := os.Stat(p)
	return err == nil && info.ModTime().UnixNano() == s.MTime
}

// indexMemoEntry 最近一次成功解码的索引缓存（单条）。stamps 是缓存里记录的
// 目录戳，供 Index 热路径校验模板目录是否仍然新鲜；root 是模板根目录
// （B2-11：IndexCached 只有缓存路径，靠缓存里记下的 root 才能校验目录戳）。
type indexMemoEntry struct {
	cachePath string
	mtime     int64
	size      int64
	root      string
	stamps    []dirStamp
	entries   []Entry
}

var (
	indexMemoMu sync.Mutex
	indexMemo   *indexMemoEntry

	// indexCacheReadHook 测试钩子：每次真正读缓存文件前回调一次（生产为 nil）。
	// 只用于断言 memo 命中时不再读文件，不参与生产逻辑。
	indexCacheReadHook func()
)

// indexMemoLoad 取与缓存文件戳匹配的 memo；无或不匹配返回 nil。
func indexMemoLoad(cachePath string, mtime, size int64) *indexMemoEntry {
	indexMemoMu.Lock()
	defer indexMemoMu.Unlock()
	m := indexMemo
	if m == nil || m.cachePath != cachePath || m.mtime != mtime || m.size != size {
		return nil
	}
	return m
}

// indexMemoStore 记录最近一次成功解码的索引（覆盖旧单条）。
func indexMemoStore(m *indexMemoEntry) {
	indexMemoMu.Lock()
	indexMemo = m
	indexMemoMu.Unlock()
}

// indexCacheStat 缓存文件戳：mtime(unixnano) + size。两个字段一起作为 memo
// 键，重建/外部改写的缓存文件必然失配。
func indexCacheStat(cachePath string) (mtime, size int64, ok bool) {
	st, err := os.Stat(cachePath)
	if err != nil {
		return 0, 0, false
	}
	return st.ModTime().UnixNano(), st.Size(), true
}

// readIndexCache 读 + 解码缓存文件；不存在/损坏/schema 不符返回 nil。
func readIndexCache(cachePath string) (*cacheFile, bool) {
	if indexCacheReadHook != nil {
		indexCacheReadHook()
	}
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, false
	}
	var cached cacheFile
	if json.Unmarshal(data, &cached) != nil || cached.Schema != cacheSchema {
		return nil, false
	}
	return &cached, true
}

// indexLoadHot Index 热路径：memo → 目录戳校验 → 缓存解码。
// 返回 (entries, true) 表示缓存有效且已命中；false 表示需要全量重建。
func indexLoadHot(dir, cachePath string) ([]Entry, bool) {
	mtime, size, ok := indexCacheStat(cachePath)
	if !ok {
		return nil, false // 无缓存：直接重建
	}
	if m := indexMemoLoad(cachePath, mtime, size); m != nil {
		if dirStampsCurrent(dir, m.stamps) {
			return m.entries, true
		}
		// 目录树已变而缓存文件未变 → 缓存必然过期。已知过期就不必再解码
		// 18MB 缓存，直接回落重建。
		return nil, false
	}
	cached, ok := readIndexCache(cachePath)
	if !ok {
		return nil, false
	}
	if !dirStampsCurrent(dir, cached.Dirs) {
		return nil, false
	}
	indexMemoStore(&indexMemoEntry{
		cachePath: cachePath, mtime: mtime, size: size,
		root: dir, stamps: cached.Dirs, entries: cached.Entries,
	})
	return cached.Entries, true
}
