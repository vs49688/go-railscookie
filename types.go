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

const (
	DefaultSignedCookieSalt          = "signed cookie"
	DefaultEncryptedCookieSalt       = "encrypted cookie"
	DefaultEncryptedSignedCookieSalt = "signed encrypted cookie"

	SessionContextKey = "rails_session"
)

type CookieCoder interface {
	Decode(s string) ([]byte, error)
	Encode(data []byte) string

	Decrypt(s string) ([]byte, error)
	Encrypt(data []byte) (string, error)
}

type Session struct {
	SessionID string `json:"session_id"`
	CSRFToken string `json:"_csrf_token"`
	LastBGSet int64  `json:"last_bg_set"`
	BG        int64  `json:"bg"`
}
