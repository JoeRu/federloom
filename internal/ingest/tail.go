package ingest

import "os"

// tailPos tracks how far a polling tailer has read a log file, and notices
// when the file at the configured path is no longer the one it was reading.
type tailPos struct {
	offset   int64
	lastSize int64
	lastFile os.FileInfo
}

// sync must be called with the Stat result of each newly opened file before
// seeking. It resets the offset to 0 when the file was truncated (smaller than
// last time) or replaced (rename-style rotation: a different inode at the same
// path). Size alone misses a replacement that is already larger than the old
// file by the next poll, which would resume mid-file and silently skip the new
// file's prefix.
func (p *tailPos) sync(fi os.FileInfo) {
	if fi.Size() < p.lastSize || (p.lastFile != nil && !os.SameFile(p.lastFile, fi)) {
		p.offset = 0
	}
	p.lastSize = fi.Size()
	p.lastFile = fi
}
