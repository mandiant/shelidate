// Copyright 2024 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package shelidate

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

//go:embed shelidate.bin
var shelidate []byte

func inetaton(host string) uint32 {
	res := big.NewInt(0)
	res.SetBytes(net.ParseIP(host).To4())
	return uint32(res.Uint64())
}

type val struct{}

type Server struct {
	address string
	l       net.Listener
	mu      sync.Mutex
	ch      map[uint32]chan<- val
}

type Shellcode struct {
	Path   string
	Recv   <-chan val
	Cancel Cancel
}

type Cancel func()

func (s *Server) Listen(address string) error {
	var err error
	s.l, err = net.Listen("tcp", address)
	if err != nil {
		return err
	}
	s.address = address
	go func() {
		for {
			conn, err := s.l.Accept()
			if err != nil {
				return
			}

			go s.handle(conn)
		}
	}()
	return nil
}

func (s *Server) Close() error {
	return s.l.Close()
}

func (s *Server) handle(conn net.Conn) error {
	defer conn.Close()
	var value uint32
	if err := binary.Read(conn, binary.LittleEndian, &value); err != nil {
		return err
	}

	s.mu.Lock()
	if s.ch != nil {
		ch, ok := s.ch[value]
		s.mu.Unlock()
		if ok {
			ch <- val{}
		}
	} else {
		s.mu.Unlock()
	}

	return nil
}

func (s *Server) Generate(dir string, value uint32) (Shellcode, error) {
	if s.address == "" {
		return Shellcode{}, fmt.Errorf("must be listening before generating shellcode")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ch == nil {
		s.ch = make(map[uint32]chan<- val)
	}

	_, ok := s.ch[value]
	if ok {
		return Shellcode{}, fmt.Errorf("value already in use")
	}

	host, port, err := net.SplitHostPort(s.address)
	if err != nil {
		return Shellcode{}, fmt.Errorf("failed to parse listen address: %v", err)
	}

	uPort, err := strconv.ParseUint(port, 10, 32)
	if err != nil {
		return Shellcode{}, fmt.Errorf("failed to parse listen address: %v", err)
	}

	uHost := inetaton(host)

	var b bytes.Buffer
	if _, err := b.Write([]byte{0xEB, 0x13, 0x58, 0xB9}); err != nil {
		return Shellcode{}, fmt.Errorf("failed to prep shellcode: %v", err)
	}

	if err := binary.Write(&b, binary.BigEndian, uint16(uPort)); err != nil {
		return Shellcode{}, fmt.Errorf("failed to prep shellcode: %v", err)
	}

	if _, err := b.Write([]byte{0x00, 0x00}); err != nil {
		return Shellcode{}, fmt.Errorf("failed to prep shellcode: %v", err)
	}

	if err := b.WriteByte(0xBA); err != nil {
		return Shellcode{}, fmt.Errorf("failed to prep shellcode: %v", err)
	}

	if err := binary.Write(&b, binary.BigEndian, uHost); err != nil {
		return Shellcode{}, fmt.Errorf("failed to prep shellcode: %v", err)
	}

	if _, err := b.Write([]byte{0x41, 0xB8}); err != nil {
		return Shellcode{}, fmt.Errorf("failed to prep shellcode: %v", err)
	}

	if err := binary.Write(&b, binary.LittleEndian, value); err != nil {
		return Shellcode{}, fmt.Errorf("failed to prep shellcode: %v", err)
	}

	if _, err := b.Write([]byte{0xFF, 0xE0, 0xE8, 0xE8, 0xFF, 0xFF, 0xFF}); err != nil {
		return Shellcode{}, fmt.Errorf("failed to prep shellcode: %v", err)
	}

	out := filepath.Join(dir, fmt.Sprintf("shellcode_%d.bin", value))

	fd, err := os.Create(out)
	if err != nil {
		return Shellcode{}, fmt.Errorf("failed to create shellcode file: %v", err)
	}
	defer fd.Close()

	if _, err := io.Copy(fd, &b); err != nil {
		return Shellcode{}, fmt.Errorf("failed to write shellcode file: %v", err)
	}

	if _, err := fd.Write(shelidate); err != nil {
		return Shellcode{}, fmt.Errorf("failed to write shellcode file: %v", err)
	}

	ch := make(chan val)
	s.ch[value] = ch

	return Shellcode{
		Path: out,
		Recv: ch,
		Cancel: func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			delete(s.ch, value)
		},
	}, nil
}
