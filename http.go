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
	"context"
	"encoding/json"
	"net/http"
)

func DecodeCookie(cc CookieCoder, ck *http.Cookie, ignoreValidity bool) (string, error) {
	if !ignoreValidity {
		if err := ck.Valid(); err != nil {
			return "", err
		}
	}

	return DecodeString(cc, ck.Value)
}

func DecryptCookie(cc CookieCoder, ck *http.Cookie, ignoreValidity bool) (string, error) {
	if !ignoreValidity {
		if err := ck.Valid(); err != nil {
			return "", err
		}
	}

	return DecryptString(cc, ck.Value)
}

func DecryptSessionCookie(cc CookieCoder, ck *http.Cookie, ignoreValidity bool) (*Session, error) {
	raw, err := DecryptCookie(cc, ck, ignoreValidity)
	if err != nil {
		return nil, err
	}

	ses := &Session{}
	if err := json.Unmarshal([]byte(raw), ses); err != nil {
		return nil, err
	}

	return ses, nil
}

func ApplySession(dec CookieCoder, req *http.Request) *http.Request {
	ck, err := req.Cookie("_session_id")
	if err != nil {
		return req
	}

	ses, err := DecryptSessionCookie(dec, ck, false)
	if err != nil {
		return req
	}

	return req.WithContext(context.WithValue(req.Context(), SessionContextKey, ses))
}

func WithSession(handler http.Handler, dec CookieCoder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		handler.ServeHTTP(w, ApplySession(dec, req))
	})
}

func RetrieveSession(ctx context.Context) *Session {
	rs, ok := ctx.Value(SessionContextKey).(*Session)
	if !ok {
		return nil
	}

	return rs
}
