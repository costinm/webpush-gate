package mesh

// From: github.com/soheilhy/cmux

// Copyright 2016 The CMux Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

import (
	"bytes"
	"io"
)

// BufferedReader is an optimized implementation of io.Reader that behaves like
// ```
// io.MultiReader(bytes.NewReader(buffer.Bytes()), io.TeeReader(source, buffer))
// ```
// without allocating.
type BufferedReader struct {
	source     io.Reader
	buffer     bytes.Buffer

	// read so far from buffer. Unread data in bufferRead:bufferSize
	bufferRead int

	// number of bytes in buffer
	bufferSize int

	// if true, anything read will be added to buffer.
	sniffing   bool

	// If an error happened while sniffing
	lastErr    error
}

func (s *BufferedReader) Read(p []byte) (int, error) {
	if s.bufferSize > s.bufferRead {
		// If we have already read something from the buffer before, we return the
		// same data and the last error if any. We need to immediately return,
		// otherwise we may block for ever, if we try to be smart and call
		// source.Read() seeking a little bit of more data.
		bn := copy(p, s.buffer.Bytes()[s.bufferRead:s.bufferSize])
		s.bufferRead += bn
		return bn, s.lastErr
	} else if !s.sniffing && s.buffer.Cap() != 0 {
		// We don't need the buffer anymore.
		// Reset it to release the internal slice.
		s.buffer = bytes.Buffer{}
	}

	// If there is nothing more to return in the sniffed buffer, read from the
	// source.
	sn, sErr := s.source.Read(p)
	if sn > 0 && s.sniffing {
		s.lastErr = sErr
		if wn, wErr := s.buffer.Write(p[:sn]); wErr != nil {
			return wn, wErr
		}
	}
	return sn, sErr
}

func (s *BufferedReader) Reset(snif bool) {
	s.sniffing = snif
	s.bufferRead = 0
	s.bufferSize = s.buffer.Len()
}
