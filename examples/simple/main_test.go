package main

import (
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mandiant/shelidate"
)

var s shelidate.Server

func TestGenerate(t *testing.T) {
	tmpdir := t.TempDir()
	sh, err := s.Generate(tmpdir, rand.Uint32())
	if err != nil {
		t.Fatalf("failed to generate test shellcode: %v", err)
	}

	out := filepath.Join(tmpdir, "main.exe")

	if err := generate(sh.Path, out); err != nil {
		t.Fatalf("failed to generate payload: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-sh.Recv
	}()
	if _, err := exec.Command(out).CombinedOutput(); err != nil {
		t.Fatalf("failed to exec payload: %v", err)
	}
	wg.Wait()
}

func TestMain(m *testing.M) {
	if err := s.Listen("127.0.0.1:13373"); err != nil {
		os.Exit(1)
	}
	defer s.Close()

	code := m.Run()
	os.Exit(code)
}
