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

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_subscriber_cert_issued_by_compromised_emudhra_ca",
			Description:   "Subscriber certificates issued by one of the eMudhra intermediate CAs whose private keys were compromised are untrustworthy",
			Citation:      "https://bugzilla.mozilla.org/show_bug.cgi?id=2083449 (eMudhra: Private key compromise of Intermediate Certificates), comments 1 and 3 list the affected intermediates",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewSubscriberCertIssuedByCompromisedEmudhraCA,
	})
}

type subscriberCertIssuedByCompromisedEmudhraCA struct{}

func NewSubscriberCertIssuedByCompromisedEmudhraCA() lint.LintInterface {
	return &subscriberCertIssuedByCompromisedEmudhraCA{}
}

// compromisedEmudhraSKIs holds the Subject Key Identifiers (hex) of the eight
// compromised eMudhra intermediate CA keys. Each key was certified twice, once
// by the emSign root and once cross-signed by Sectigo, and both certificates
// carry the same SKI, so one entry covers both.
var compromisedEmudhraSKIs = map[string]string{
	"3edc20d9894698877b873fd88147b25c15d84706": "EM EV TLS CA - G3B",
	"9bd86551afe7e72c37ad08ee6919d9bf3784ae0a": "EM OV TLS CA - G3B",
	"e21e2fe71c19390e554b62c120245735248a2514": "EM DV TLS CA - G3B",
	"a6255e80a94db7f3967c1bc791df92bcee4beb5f": "EM EV TLS CA - G3C",
	"34eaea0cebc90adaf9d0c5e2ed9b78c9879e1b6c": "EM OV TLS CA - G3C",
	"ae7e105c3c2996c1a847270559f1e03dd4e50af3": "EM DV TLS CA - G3C",
	"79fae8eccfdb0d758da458d69fb6eddc7c49dee6": "EM OV CS CA - G3B",
	"ee6f73298d6fbfa7b31bc39534f61556447866b7": "EM OV CS CA - G3C",
}

func (l *subscriberCertIssuedByCompromisedEmudhraCA) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && len(c.AuthorityKeyId) > 0
}

func (l *subscriberCertIssuedByCompromisedEmudhraCA) Execute(c *x509.Certificate) *lint.LintResult {
	if _, ok := compromisedEmudhraSKIs[hex.EncodeToString(c.AuthorityKeyId)]; ok {
		return &lint.LintResult{Status: lint.Error}
	}
	return &lint.LintResult{Status: lint.Pass}
}
