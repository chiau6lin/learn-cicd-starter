package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
		expectErrMsg  string
	}{
		{
			name:          "no authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - no space",
			headers: http.Header{
				"Authorization": []string{"ApiKeymy-secret-key"},
			},
			expectedKey:  "",
			expectErrMsg: "malformed authorization header",
		},
		{
			name: "malformed header - wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-key"},
			},
			expectedKey:  "",
			expectErrMsg: "malformed authorization header",
		},
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			expectedKey:   "my-secret-key",
			expectedError: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			// 檢查 key
			if key != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, key)
			}

			// 檢查 sentinel error
			if tc.expectedError != nil {
				if err != tc.expectedError {
					t.Errorf("expected error %v, got %v", tc.expectedError, err)
				}
				return
			}

			// 檢查 error message
			if tc.expectErrMsg != "" {
				if err == nil {
					t.Errorf("expected error with message %q, got nil", tc.expectErrMsg)
					return
				}
				if err.Error() != tc.expectErrMsg {
					t.Errorf("expected error message %q, got %q", tc.expectErrMsg, err.Error())
				}
				return
			}

			// 預期無錯誤
			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
