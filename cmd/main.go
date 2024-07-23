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
package main

import (
	"bytes"
	"context"
	"flag"
	"html/template"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/mandiant/shelidate"
)

var address = flag.String("address", "127.0.0.1:1337", "shellcode listener address")
var command = flag.String("command", "", "command to execute while listening, use {{.Shellcode}} to substitute the shellcode file")
var timeout = flag.String("timeout", "30s", "timeout duration (only used if commmand is specified)")

type Variables struct {
	Shellcode string
}

func main() {
	flag.Parse()

	var svr shelidate.Server

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	wg := new(sync.WaitGroup)

	if err := svr.Listen(*address); err != nil {
		log.Fatalf("failed to start listener - address: %v - error: %v", *address, err)
	}

	log.Printf("callback server listening - address: %v", *address)

	dir, err := os.Getwd()
	if err != nil {
		log.Fatalf("failed to get working directory - error: %v", err)
	}

	shellcode, err := svr.Generate(dir, rand.Uint32())
	if err != nil {
		log.Fatalf("failed to generate shellcode - error: %v", err)
	}
	defer os.Remove(shellcode.Path)

	log.Printf("generated test shellcode: %v", shellcode.Path)

	var cmd string
	if *command != "" {
		tmpl, err := template.New("command").Parse(*command)
		if err != nil {
			log.Fatalf("failed to template provided command - command: %v - error: %v", command, err)
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(
			&buf,
			Variables{
				Shellcode: shellcode.Path,
			},
		); err != nil {
			log.Fatalf("failed to template provided command - command: %v - error: %v", command, err)
		}

		cmd = buf.String()
	}

	wg.Add(1)

	var ctx context.Context
	var cancel context.CancelFunc

	if cmd != "" {
		duration, err := time.ParseDuration(*timeout)
		if err != nil {
			log.Fatalf("failed to parse provided timeout - timout: %v - error: %v", *timeout, err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), duration)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}

	go func() {
		defer wg.Done()
		defer svr.Close()
		defer shellcode.Cancel()
		defer cancel()

		for {
			select {
			case <-c:
				return
			case <-ctx.Done():
				return
			case <-shellcode.Recv:
				log.Printf("test shellcode checked in")
				if cmd != "" {
					time.Sleep(500 * time.Millisecond)
					return
				}
			}
		}
	}()

	if cmd != "" {
		log.Printf("running the command: %v", cmd)
		if err := exec.CommandContext(ctx, "C:\\Windows\\System32\\cmd.exe", "/c", cmd).Run(); err != nil {
			log.Fatalf("command failed to run: %v", err)
		}
	}

	wg.Wait()
}
