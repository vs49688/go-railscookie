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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionExtraction(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	req.AddCookie(&http.Cookie{
		Name:  "_session_id",
		Value: "YmN0dStGMFJLR2MzL2F5TXk3dHFzNzBZWnZNSFl4QmRoSDhmOWtqNFNNR0VZKzl3aDZTeGFCR3ZBS2xPMWttbUJ5aDNOb09KNElld3lHTGdNc3BIUytnOEdsdUJXQnR4N3VSUGFjak1mdmZ3b1dleDlQUzhVNmlGNmp0dndjWWo1dDIraTdsSFRwT09sNVFXYWpOTlhueWQ5WDhVSmxLUGlxRjQvcnBpejdBdmNGUThmQmd3TTNLcXArMlp5TS9ULS1BWlQ5d3Zvdi9NQkIwLzhTQkZ0enlBPT0%3D--42fd2c2c5562f3af1198a2eb199a91e8ff334109",
	})

	resp := httptest.NewRecorder()

	cc := makeTestCoder(t)

	handler := WithSession(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rs := RetrieveSession(req.Context())
		require.NotNil(t, rs)
		assert.Equal(t, &Session{
			SessionID: "47447fd1fd187c92b52caf7e424dab9a",
			CSRFToken: "IM7teCxrFyouGlSTNv9SVfs7O/qH4W8WK1BiRg5nzuw=",
			LastBGSet: 1688208839,
			BG:        14,
		}, rs)
		w.WriteHeader(http.StatusOK)

	}), cc)

	handler.ServeHTTP(resp, req)
}
