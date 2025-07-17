package auth

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		input       http.Header
		want        string
		expectedErr error
	}{
		"simple": {
			input: http.Header{
				"Authorization": []string{"ApiKey 123SensitiveString321"},
			},
			want:        "123SensitiveString321",
			expectedErr: nil,
		},
		"two spaces after Apikey": {
			input: http.Header{
				"Authorization": []string{"ApiKey  123SensitiveString321"},
			},
			want:        "",
			expectedErr: MalformedAuthHeader,
		},
		"leading space prior to Apikey": {
			input: http.Header{
				"Authorization": []string{" ApiKey 123SensitiveString321"},
			},
			want:        "",
			expectedErr: MalformedAuthHeader,
		},
		"Header key is empty": {
			input: http.Header{
				"": []string{"ApiKey 123SensitiveString321"},
			},
			want:        "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		"Authorization header is mispelled/not exact": {
			input: http.Header{
				"Autha": []string{"ApiKey 123SensitiveString321"},
			},
			want:        "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		"Authorization header is lower cased": {
			input: http.Header{
				"authorization": []string{"ApiKey 123SensitiveString321"},
			},
			want:        "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		"Authorization header is mixed cased": {
			input: http.Header{
				"AuThoRiZaTiOn": []string{"ApiKey 123SensitiveString321"},
			},
			want:        "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		"Authorization header is upper cased": {
			input: http.Header{
				"AUTHORIZATION": []string{"ApiKey 123SensitiveString321"},
			},
			want:        "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		"api key value is an empty string": {
			input: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			want:        "",
			expectedErr: nil,
		},
		"api key is missing a leading space": {
			input: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:        "",
			expectedErr: MalformedAuthHeader,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.input)
			if err != nil {
				diff := cmp.Diff(err, tc.expectedErr, cmpopts.EquateErrors())
				if diff != "" {
					t.Fatalf(diff)
				}
			}
			diff := cmp.Diff(tc.want, got)
			if diff != "" {
				t.Fatalf(diff)
			}
		})
	}
}
