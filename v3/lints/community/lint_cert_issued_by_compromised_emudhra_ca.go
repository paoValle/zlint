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
	"encoding/base64"
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cert_issued_by_compromised_emudhra_ca",
			Description:   "Certificates signed by one of the eMudhra intermediate CA keys that were compromised are untrustworthy",
			Citation:      "https://bugzilla.mozilla.org/show_bug.cgi?id=2083449 (eMudhra: Private key compromise of Intermediate Certificates), comments 1 and 3 list the affected intermediates",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewCertIssuedByCompromisedEmudhraCA,
	})
}

type certIssuedByCompromisedEmudhraCA struct{}

func NewCertIssuedByCompromisedEmudhraCA() lint.LintInterface {
	return &certIssuedByCompromisedEmudhraCA{}
}

const compromisedEmudhraBugURL = "https://bugzilla.mozilla.org/show_bug.cgi?id=2083449"

// compromisedEmudhraKeySpecs holds the base64 SubjectPublicKeyInfo of the eight
// compromised eMudhra intermediate CA keys. Each key was certified twice, once
// by the emSign root and once cross-signed by Sectigo, so one entry covers both.
//
// The signature is checked against the key itself, rather than trusting the
// Authority Key Identifier, because the AKI is chosen by whoever signs the
// certificate. The compromised private keys are trivially recoverable, so a
// certificate minted with them can carry any AKI, or none, and clients still
// chain it to these CAs by name and signature.
var compromisedEmudhraKeySpecs = []struct {
	name string
	spki string
}{
	{
		name: "EM EV TLS CA - G3B",
		spki: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEJduoWmTTl9oLEFLp6lRuSHvv6pydnWigxerc/u91ppu11vwB9Cv7ym60C81kwHZ+Nv/QXZeoE8WqDGyVMOec9fCGZGjxOAZCCqXIUYQLHiUlQOeQ5LZUw4Uu1krx6GV9",
	},
	{
		name: "EM OV TLS CA - G3B",
		spki: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEc4l6oOs8/cqLEkAv+vCrxOEhK6+N7neKye4tbbg/rCgMXgVjiueirNccMiqONhzeufacQwK53Y1z0cxsqrLMCu5OIWzped1Rikr0tiblaEzdZYA37QyFTkzBL0z4ZG0N",
	},
	{
		name: "EM DV TLS CA - G3B",
		spki: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE557ZwEqXc8RzXlERHahawr1eZKs3S4DhLLwgOOweTw47gS/JhZ4eZ6+wTi+LyX90hbplqpEe6KTkW2LVzAPVa+Z4s8OMtNyTfKJGDiOEU8iSk10p1E+R4VYGtjzO2rRo",
	},
	{
		name: "EM EV TLS CA - G3C",
		spki: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAELVboKab7gsZKRpfZYK+VHpBnrpH5JtNDBtpIqKrreGm2pn5tJ0JuBEKqA7NuGYjf9jZRTuHPB/W6Sz/yoGZFrn0x1YZq0xqj0kbrCzF37pnLdWbFFs50gIpmj5HwxH/K",
	},
	{
		name: "EM OV TLS CA - G3C",
		spki: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZfjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+N7ulaVSfHAKycO1n",
	},
	{
		name: "EM DV TLS CA - G3C",
		spki: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOnp4YsjETTJN3WkDOmeCwO/u/kBV5ooSP6A3G6O9kZRRTuFypDPjYw8CvRiAN9nlFJ+bd9uUooHfmHsv6oiLdL3+j9pMEJnubKGVZv4+8OX2sJpVbMyLpQVh3xsqRB0B",
	},
	{
		name: "EM OV CS CA - G3B",
		spki: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqrsPsGZqz88B+tUr/P1MK/LLPDSX3nOVDlgZth/mlQmHQcjEkUObNKBDHK/+W/m0wcjorgAB+fTcitgsWfNjnpbNbD1NsM7+wmw9YlF7N3YTcnQ/jordd7EAZPKr5eBQ",
	},
	{
		name: "EM OV CS CA - G3C",
		spki: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEufDgY0cCppymqt1EPP1ixBubpLIJJGl9eXTnaRoSb7lq+z40wv07xfSDBh8mXcKlhDY0cyNRBDayjwTzhiNjBnmA4lA+AlMtZUYjWnFlolmh70lvdBtf3ud4cgjkuPrv",
	},
}

type compromisedEmudhraKey struct {
	name string
	key  interface{}
}

var compromisedEmudhraKeys = parseCompromisedEmudhraKeys()

func parseCompromisedEmudhraKeys() []compromisedEmudhraKey {
	keys := make([]compromisedEmudhraKey, 0, len(compromisedEmudhraKeySpecs))
	for _, s := range compromisedEmudhraKeySpecs {
		der, err := base64.StdEncoding.DecodeString(s.spki)
		if err != nil {
			panic(fmt.Sprintf("invalid base64 for %s: %v", s.name, err))
		}
		key, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			panic(fmt.Sprintf("invalid public key for %s: %v", s.name, err))
		}
		keys = append(keys, compromisedEmudhraKey{name: s.name, key: key})
	}
	return keys
}

// CheckApplies is always true: an intermediate minted with a compromised key
// is as much a part of a chain to these CAs as a subscriber certificate is.
// This lint can only see the certificate that was signed directly by a
// compromised key, not certificates further down a chain.
func (l *certIssuedByCompromisedEmudhraCA) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *certIssuedByCompromisedEmudhraCA) Execute(c *x509.Certificate) *lint.LintResult {
	for _, k := range compromisedEmudhraKeys {
		if x509.CheckSignatureFromKey(k.key, c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
			return &lint.LintResult{
				Status: lint.Error,
				Details: fmt.Sprintf("signed by the private key of %q, an eMudhra intermediate CA whose private key was compromised; see %s",
					k.name, compromisedEmudhraBugURL),
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
