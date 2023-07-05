// Copyright 2023 Zane van Iperen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package railscookie

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const TestKeyBase = "58ab25e4e452411f11f2a36663bf9ed0592bf7a86157ee761691d768ae7ec4cd540f48f2fd702bf7bfcb9251cb32b2c1d23c7c11dbfb3f1effa5329a2d5a549d"

func makeTestCoder(t *testing.T) CookieCoder {
	cc, err := NewRails5CookieCoder(Configuration{
		SecretKeyBase:             TestKeyBase,
		SignedCookieSalt:          DefaultSignedCookieSalt,
		EncryptedSignedCookieSalt: DefaultEncryptedSignedCookieSalt,
		EncryptedCookieSalt:       DefaultEncryptedCookieSalt,
		RNG:                       rand.New(rand.NewSource(0)),
	})
	require.NoError(t, err)
	return cc
}

func TestCoding(t *testing.T) {
	tests := []struct {
		Name      string
		PlainText string
		Encoded   string
		Encrypted string
	}{
		{
			Name:      "test1",
			PlainText: "49885",
			Encoded:   "NDk4ODU%3D--2524a3daaadeedaccbe45a8046988782756e9558",
			Encrypted: "bHp0aENsWGN4L3J3MnRiTFZwS0hvdz09LS1BWlQ5d3Zvdi9NQkIwLzhTQkZ0enlBPT0%3D--4276c2e108ee6c395d9a467253edfd4770793131",
		},
		{
			Name:      "test2",
			PlainText: `{"session_id":"47447fd1fd187c92b52caf7e424dab9a","_csrf_token":"IM7teCxrFyouGlSTNv9SVfs7O/qH4W8WK1BiRg5nzuw=","last_bg_set":1688208839,"bg":14}`,
			Encoded:   "eyJzZXNzaW9uX2lkIjoiNDc0NDdmZDFmZDE4N2M5MmI1MmNhZjdlNDI0ZGFiOWEiLCJfY3NyZl90b2tlbiI6IklNN3RlQ3hyRnlvdUdsU1ROdjlTVmZzN08vcUg0VzhXSzFCaVJnNW56dXc9IiwibGFzdF9iZ19zZXQiOjE2ODgyMDg4MzksImJnIjoxNH0%3D--4276bee89dbc19ac2202e182a369134044e7828a",
			Encrypted: `YmN0dStGMFJLR2MzL2F5TXk3dHFzNzBZWnZNSFl4QmRoSDhmOWtqNFNNR0VZKzl3aDZTeGFCR3ZBS2xPMWttbUJ5aDNOb09KNElld3lHTGdNc3BIUytnOEdsdUJXQnR4N3VSUGFjak1mdmZ3b1dleDlQUzhVNmlGNmp0dndjWWo1dDIraTdsSFRwT09sNVFXYWpOTlhueWQ5WDhVSmxLUGlxRjQvcnBpejdBdmNGUThmQmd3TTNLcXArMlp5TS9ULS1BWlQ5d3Zvdi9NQkIwLzhTQkZ0enlBPT0%3D--42fd2c2c5562f3af1198a2eb199a91e8ff334109`,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("decode", func(t *testing.T) {
				val, err := DecodeString(makeTestCoder(t), test.Encoded)
				require.NoError(t, err)
				assert.Equal(t, test.PlainText, val)
			})

			t.Run("encode", func(t *testing.T) {
				val := EncodeString(makeTestCoder(t), test.PlainText)
				assert.Equal(t, test.Encoded, val)
			})

			t.Run("decrypt", func(t *testing.T) {
				val, err := DecryptString(makeTestCoder(t), test.Encrypted)
				require.NoError(t, err)
				assert.Equal(t, test.PlainText, val)
			})

			t.Run("encrypt", func(t *testing.T) {
				val, err := EncryptString(makeTestCoder(t), test.PlainText)
				require.NoError(t, err)
				assert.Equal(t, test.Encrypted, val)
			})
		})
	}
}
