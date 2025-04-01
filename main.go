package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	CacheDir = "cache"
)

var (
	lock             sync.Mutex
	searchedPrefixes = map[string]*sync.RWMutex{}
)

func check(hash string) (bool, error) {
	hash = strings.ToUpper(hash)
	prefix := hash[:5]
	oldEtag := attemptLoadEtag(prefix)
	cacheDir := filepath.Join(CacheDir, prefix)

	lock.Lock()
	prefixLock, ok := searchedPrefixes[prefix]
	if !ok {
		prefixLock = &sync.RWMutex{}
		searchedPrefixes[prefix] = prefixLock
		prefixLock.Lock()
		defer prefixLock.Unlock()

		lock.Unlock()

	} else {
		lock.Unlock()

		prefixLock.RLock()
		defer prefixLock.RUnlock()
	}

	if ok {
		f, err := os.Open(filepath.Join(cacheDir, "data"))
		if err != nil {
			return false, fmt.Errorf("failed to open data file: %w", err)
		}
		defer f.Close()

		return searchFile(hash, f)
	}

	req, err := http.NewRequest(http.MethodGet, "https://api.pwnedpasswords.com/range/"+prefix+"?mode=ntlm", nil)
	if err != nil {
		return false, fmt.Errorf("Failed to construct query to pwndpasswords: %w", err)
	}

	if oldEtag != "" {
		req.Header.Set("If-None-Match", oldEtag)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("Failed to query pwndpasswords: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 304 {
		// we already have the data file, and the etag is not invalid so we can just load this here

		f, err := os.Open(filepath.Join(cacheDir, "data"))
		if err != nil {
			return false, fmt.Errorf("failed to open data file: %w", err)
		}
		defer f.Close()

		return searchFile(hash, f)
	}

	err = os.MkdirAll(cacheDir, 0700)
	if err != nil {
		return false, fmt.Errorf("failed to create cache directories: %w", err)
	}

	etag := res.Header.Get("etag")
	err = os.WriteFile(filepath.Join(cacheDir, "etag"), []byte(etag), 0600)
	if err != nil {
		return false, fmt.Errorf("failed to create etag store: %w", err)
	}

	f, err := os.OpenFile(filepath.Join(cacheDir, "data"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return false, fmt.Errorf("failed to open hashes store: %w", err)
	}
	defer f.Close()

	_, err = io.Copy(f, &Stripper{r: res.Body})
	if err != nil {
		return false, fmt.Errorf("failed to write to hashes store: %w", err)
	}

	return searchFile(hash, f)

}

func attemptLoadEtag(prefix string) string {
	etag, err := os.ReadFile(filepath.Join(CacheDir, prefix, "etag"))
	if err != nil {
		log.Println("no etag for: ", prefix, err)
		return ""
	}

	return strings.TrimSpace(string(etag))
}

func searchFile(hash string, f *os.File) (bool, error) {
	f.Seek(0, 0)

	info, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("failed to get size: %w", err)
	}

	lower := int64(0)
	// hash suffix is 27 bytes (32-5) and we have one character for newline
	upper := info.Size() / 28
	line := ""
	hashSuffix := hash[5:]
	for upper-lower >= 1 {
		middle := (upper + lower) / 2
		f.Seek(middle*28, 0)
		hashBytes := make([]byte, 27)
		n, err := f.Read(hashBytes)
		if err != nil {
			log.Fatal(err)
		}

		if n != 27 {
			log.Fatal("short line")
		}
		line = string(hashBytes)

		if line > hashSuffix {
			upper = middle
		} else if line < hashSuffix {
			lower = middle + 1
		} else {
			break
		}
	}

	return hashSuffix == line, nil

}

func main() {

	hash := flag.String("hash", "21BD1FAA3BB7F0FBDBBE55A0BF95261B", "Hash to check in hibp")

	hashesFile := flag.String("file", "", "Hashes to check")

	flag.Parse()

	if *hashesFile != "" {
		f, err := os.Open(*hashesFile)
		if err != nil {
			log.Fatal("could not open file full of hashes: ", err)
		}
		defer f.Close()

		type Result struct {
			hash  string
			found bool
		}

		limit := make(chan struct{}, 10)
		output := make(chan Result)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			hash := strings.TrimSpace(scanner.Text())
			if len(hash) != 32 {
				log.Fatal("hash is an invalid length: ", hash, "should be 32 was: ", len(hash))
				continue
			}

			limit <- struct{}{}
			go func() {
				defer func() {
					<-limit
				}()
				found, err := check(hash)
				if err != nil {
					log.Println(err)
					return
				}

				output <- Result{
					found: found,
					hash:  hash,
				}
			}()

		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
		return
	}

	if len(*hash) != 32 {
		log.Fatal("hash is an invalid length")
	}

	*hash = strings.ToUpper(*hash)
	log.Println(check(*hash))

}

type Stripper struct {
	r        io.Reader
	leftOver []byte
}

func (s *Stripper) Read(b []byte) (n int, err error) {

	if len(s.leftOver) > 0 {
		n := copy(b, s.leftOver)
		s.leftOver = s.leftOver[n:]
		return n, nil
	}

	s.leftOver = make([]byte, 28)
	s.leftOver[27] = '\n'

	read := 0
	for read < 27 {
		n, err = s.r.Read(s.leftOver[read:27])

		read += n

		if err != nil {
			return n, err
		}
	}

	n = copy(b, s.leftOver)
	s.leftOver = s.leftOver[n:]

	single := make([]byte, 1)
	for {
		_, err = s.r.Read(single)
		if err != nil {
			return n, err
		}

		if single[0] == '\n' {
			break
		}
	}

	return
}
