package engine

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
	"github.com/Undrocs/wardline/internal/security"
)

// maxWalkDepth bounds directory recursion so a pathological tree cannot exhaust
// the stack or the scanner's time budget.
const maxWalkDepth = 64

// walkStats records traversal side effects that must be visible in reports.
type walkStats struct {
	Files         int
	Bytes         int64
	Symlinks      int
	SkippedLarge  int
	SkippedDeep   int
	Irregular     int
	LimitReached  bool
	MaxFilesLimit int
}

// collectFiles walks root once and returns the candidate files.
//
// Rules:
//   - symbolic links are never followed (neither files nor directories);
//   - .git and other vendored/cache directories are pruned;
//   - configured exclusions are applied to directories and files;
//   - files above the size limit are skipped for content scanning and counted;
//   - exceeding the file-count limit is an error, because a truncated file list
//     would make the scan silently incomplete.
func collectFiles(ctx context.Context, root string, cfg *config.Config) ([]scanners.File, walkStats, error) {
	var (
		stats walkStats
		files []scanners.File
	)
	stats.MaxFilesLimit = cfg.Limits.MaxFiles

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable entries are recorded but do not abort the walk: a
			// permission problem in an unrelated directory must not hide the
			// rest of the repository.
			stats.Irregular++
			if path == root {
				return err
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, relErr := security.NormalizeRel(root, path)
		if relErr != nil {
			stats.Irregular++
			return nil
		}
		if rel == "" {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			stats.Symlinks++
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if excluded(rel, cfg.Exclude) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if security.IsGeneratedPath(rel) {
				return filepath.SkipDir
			}
			if depth(rel) > maxWalkDepth {
				// Pruning silently would make the scan look complete while part
				// of the tree was never examined, so it is counted and reported.
				stats.SkippedDeep++
				return filepath.SkipDir
			}
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			stats.Irregular++
			return nil
		}
		if !info.Mode().IsRegular() {
			stats.Irregular++
			return nil
		}
		if info.Size() > cfg.Limits.MaxFileSize {
			stats.SkippedLarge++
			return nil
		}
		if len(files)+1 > cfg.Limits.MaxFiles {
			stats.LimitReached = true
			return fmt.Errorf("file count limit reached (%d); narrow the scan with --exclude or raise limits.maxFiles", cfg.Limits.MaxFiles)
		}
		abs, absErr := filepath.Abs(path)
		if absErr != nil {
			stats.Irregular++
			return nil
		}
		files = append(files, scanners.File{Rel: rel, Abs: abs, Size: info.Size()})
		stats.Files++
		stats.Bytes += info.Size()
		return nil
	})
	if walkErr != nil {
		return nil, stats, walkErr
	}
	if err := ctx.Err(); err != nil {
		return nil, stats, err
	}
	return files, stats, nil
}

func excluded(rel string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	if findings.MatchesAnyGlob(rel, patterns) {
		return true
	}
	// A pattern such as "generated/**" must also prune the directory itself.
	return findings.MatchesAnyGlob(rel+"/", patterns)
}

func depth(rel string) int {
	n := 1
	for i := 0; i < len(rel); i++ {
		if rel[i] == '/' {
			n++
		}
	}
	return n
}
