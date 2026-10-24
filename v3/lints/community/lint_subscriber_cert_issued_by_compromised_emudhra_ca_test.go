/*
 * ZLint Copyright 2026 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package community

import (
	"encoding/hex"
	"testing"

	"github.com/zmap/zcrypto/x509"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func TestSubscriberCertIssuedByCompromisedEmudhraCA(t *testing.T) {
	testCases := []struct {
		name      string
		inputPath string
		expected  lint.LintStatus
	}{
		{"first compromised SKI", "subscriberIssuedByCompromisedEmudhraCAEvG3B.pem", lint.Error},
		{"last compromised SKI", "subscriberIssuedByCompromisedEmudhraCACsG3C.pem", lint.Error},
		{"unrelated issuer", "subscriberIssuedByUnrelatedCA.pem", lint.Pass},
		{"CA certificate is not a subscriber", "caIssuedByCompromisedEmudhraCAAKI.pem", lint.NA},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := test.TestLint("e_subscriber_cert_issued_by_compromised_emudhra_ca", tc.inputPath)
			if out.Status != tc.expected {
				t.Errorf("%s: expected %s, got %s", tc.inputPath, tc.expected, out.Status)
			}
		})
	}
}

func TestSubscriberCertIssuedByCompromisedEmudhraCAAllSKIs(t *testing.T) {
	for _, ski := range []string{
		"3edc20d9894698877b873fd88147b25c15d84706", // EM EV TLS CA - G3B
		"9bd86551afe7e72c37ad08ee6919d9bf3784ae0a", // EM OV TLS CA - G3B
		"e21e2fe71c19390e554b62c120245735248a2514", // EM DV TLS CA - G3B
		"a6255e80a94db7f3967c1bc791df92bcee4beb5f", // EM EV TLS CA - G3C
		"34eaea0cebc90adaf9d0c5e2ed9b78c9879e1b6c", // EM OV TLS CA - G3C
		"ae7e105c3c2996c1a847270559f1e03dd4e50af3", // EM DV TLS CA - G3C
		"79fae8eccfdb0d758da458d69fb6eddc7c49dee6", // EM OV CS CA - G3B
		"ee6f73298d6fbfa7b31bc39534f61556447866b7", // EM OV CS CA - G3C
	} {
		keyID, err := hex.DecodeString(ski)
		if err != nil {
			t.Fatal(err)
		}
		c := &x509.Certificate{AuthorityKeyId: keyID}
		if out := NewSubscriberCertIssuedByCompromisedEmudhraCA().Execute(c); out.Status != lint.Error {
			t.Errorf("%s: expected %s, got %s", ski, lint.Error, out.Status)
		}
	}
}
