// SPDX-License-Identifier: Apache-2.0
//
// EP timestamp-proof (RFC 3161) — Go port of packages/verify/timestamp-proof.js.
//
// An INDEPENDENT proof of WHEN: verify a standards-track RFC 3161 TimeStampToken
// (a CMS/PKCS#7 SignedData carrying a TSTInfo) minted by an EXTERNAL TSA against
// a PINNED TSA public key. Same contract as the JS reference: ASYMMETRIC,
// key-PINNED, FAIL-CLOSED. An unpinned/unknown TSA REFUSES; a messageImprint that
// is not the caller's expected digest REFUSES; a signature that does not verify
// under the pinned key REFUSES; an unparseable token REFUSES. Nothing defaults to
// "trusted".
//
// PARSING BOUNDARY (honest, identical to the JS and Python ports): this is a
// PURPOSE-BUILT minimal DER/CMS reader. Go's encoding/asn1 does not round-trip
// the CMS SignedData IMPLICIT/EXPLICIT context tagging the way the byte-exact
// re-encode of SignedAttributes (RFC 5652 §5.4) and the eContent hashing require,
// so the structural parse is hand-rolled here (no new dependency; only stdlib
// crypto/* is used for the RSA/ECDSA signature verification). Supports a single
// SignerInfo, RSA (RSASSA-PKCS1-v1_5) or ECDSA over a SHA-2 digest, with OR
// without CMS signed attributes. Does NOT implement X.509 path building (caller
// PINS the exact key), RSASSA-PSS, or multi-signer tokens; anything outside the
// supported shape REFUSES with a distinct reason.
//
// WHAT THIS PROVES (and only this): a TSA the caller chose to pin asserted, with
// its signature, that expectedDigest existed at genTime (the bytes PREDATE
// genTime). It does NOT prove the action was correct/authorized, does not prove
// the TSA clock was accurate, and — like every offline check here — says nothing
// about CURRENT validity or revocation of the TSA certificate.
package emiliaverify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
)

const TimestampProofAlg = "RFC3161"

// ── OIDs we recognize (dotted string form) ───────────────────────────────────
const (
	tspOidSignedData    = "1.2.840.113549.1.7.2"      // pkcs7-signedData
	tspOidCtTSTInfo     = "1.2.840.113549.1.9.16.1.4" // id-ct-TSTInfo (eContentType)
	tspOidContentType   = "1.2.840.113549.1.9.3"      // id-contentType signed attr
	tspOidMessageDigest = "1.2.840.113549.1.9.4"      // id-messageDigest signed attr
	tspOidSHA256        = "2.16.840.1.101.3.4.2.1"
	tspOidSHA384        = "2.16.840.1.101.3.4.2.2"
	tspOidSHA512        = "2.16.840.1.101.3.4.2.3"
	tspOidRSAEncryption = "1.2.840.113549.1.1.1" // rsaEncryption (PKCS1 v1.5)
	tspOidECDSASHA256   = "1.2.840.10045.4.3.2"
	tspOidECDSASHA384   = "1.2.840.10045.4.3.3"
	tspOidECDSASHA512   = "1.2.840.10045.4.3.4"
)

// SHA-2 only, deliberately: a SHA-1 digest OID refuses with
// unsupported_digest_algorithm.
var tspDigestOIDToName = map[string]string{
	tspOidSHA256: "sha256",
	tspOidSHA384: "sha384",
	tspOidSHA512: "sha512",
}

// TimestampProofResult mirrors the JS { verified, tsa_key_id, gen_time, reason }
// shape. On refusal, Verified is false and Reason carries a distinct string; on
// success TSAKeyID and GenTime are populated and Reason is empty.
type TimestampProofResult struct {
	Verified bool   `json:"verified"`
	TSAKeyID string `json:"tsa_key_id"`
	GenTime  string `json:"gen_time"`
	Reason   string `json:"reason,omitempty"`
}

func tspRefuse(reason string) TimestampProofResult {
	return TimestampProofResult{Verified: false, Reason: reason}
}

// tspDerError signals any structural malformation; the top-level verifier turns
// it into a fail-closed unparseable_token refusal (mirrors DerError in JS).
type tspDerError struct{ msg string }

func (e *tspDerError) Error() string { return e.msg }

// tspNode is one DER TLV. Every accessor is bounds-checked at parse time.
type tspNode struct {
	cls          int
	constructed  bool
	tag          int
	headerLen    int
	contentStart int
	contentEnd   int
	buf          []byte
}

func (n *tspNode) content() []byte { return n.buf[n.contentStart:n.contentEnd] }

// raw returns header+content bytes (used to re-hash eContent / re-encode
// SignedAttributes).
func (n *tspNode) raw() []byte { return n.buf[n.contentStart-n.headerLen : n.contentEnd] }

// tspReadTLV mirrors readTLV in the JS reference. Returns a node or a tspDerError
// on any truncation/over-long field.
func tspReadTLV(buf []byte, offset int) (*tspNode, error) {
	if offset+2 > len(buf) {
		return nil, &tspDerError{"truncated TLV header"}
	}
	first := buf[offset]
	cls := int(first&0xc0) >> 6
	constructed := (first & 0x20) != 0
	tag := int(first & 0x1f)
	p := offset + 1
	if tag == 0x1f {
		tag = 0
		for {
			if p >= len(buf) {
				return nil, &tspDerError{"truncated high tag"}
			}
			b := buf[p]
			p++
			tag = (tag << 7) | int(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
	}
	if p >= len(buf) {
		return nil, &tspDerError{"truncated length"}
	}
	length := int(buf[p])
	p++
	if length&0x80 != 0 {
		numBytes := length & 0x7f
		if numBytes == 0 {
			return nil, &tspDerError{"indefinite length not allowed in DER"}
		}
		if numBytes > 4 {
			return nil, &tspDerError{"length too large"}
		}
		if p+numBytes > len(buf) {
			return nil, &tspDerError{"truncated long length"}
		}
		length = 0
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(buf[p])
			p++
		}
	}
	contentStart := p
	contentEnd := p + length
	if contentEnd > len(buf) {
		return nil, &tspDerError{"content exceeds buffer"}
	}
	return &tspNode{cls, constructed, tag, contentStart - offset, contentStart, contentEnd, buf}, nil
}

// tspChildren iterates the child TLVs of a constructed node. On a malformed child
// it returns the error via the second return value.
func tspChildren(node *tspNode) ([]*tspNode, error) {
	out := []*tspNode{}
	p := node.contentStart
	for p < node.contentEnd {
		child, err := tspReadTLV(node.buf, p)
		if err != nil {
			return nil, err
		}
		out = append(out, child)
		p = child.contentEnd
	}
	return out, nil
}

func tspDecodeOID(node *tspNode) (string, error) {
	if node.tag != 0x06 || node.cls != 0 {
		return "", &tspDerError{"expected OID"}
	}
	b := node.content()
	if len(b) == 0 {
		return "", &tspDerError{"empty OID"}
	}
	first := int(b[0])
	parts := []int{first / 40, first % 40}
	value := 0
	for i := 1; i < len(b); i++ {
		value = (value << 7) | int(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			parts = append(parts, value)
			value = 0
		}
	}
	sb := strings.Builder{}
	for i, v := range parts {
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteString(itoaTsp(v))
	}
	return sb.String(), nil
}

func itoaTsp(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var digs [20]byte
	i := len(digs)
	for v > 0 {
		i--
		digs[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		digs[i] = '-'
	}
	return string(digs[i:])
}

var (
	tspGenTimeRe = regexp.MustCompile(`^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$`)
	tspUTCTimeRe = regexp.MustCompile(`^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$`)
)

// tspDecodeGeneralizedTime -> RFC 3339 UTC iso string, or "" (fail-closed) on any
// non-conforming form. Mirrors decodeGeneralizedTime.
func tspDecodeGeneralizedTime(node *tspNode) string {
	s := string(node.content())
	if node.tag == 0x18 {
		if m := tspGenTimeRe.FindStringSubmatch(s); m != nil {
			frac := m[7]
			return m[1] + "-" + m[2] + "-" + m[3] + "T" + m[4] + ":" + m[5] + ":" + m[6] + frac + "Z"
		}
	}
	if node.tag == 0x17 {
		if m := tspUTCTimeRe.FindStringSubmatch(s); m != nil {
			yy := (int(m[1][0]-'0') * 10) + int(m[1][1]-'0')
			year := 1900 + yy
			if yy < 50 {
				year = 2000 + yy
			}
			return itoaTsp(year) + "-" + m[2] + "-" + m[3] + "T" + m[4] + ":" + m[5] + ":" + m[6] + "Z"
		}
	}
	return ""
}

var tspHexRe = regexp.MustCompile(`^[0-9a-f]+$`)

// tspHexOf normalizes a digest input ("sha256:<hex>" | "<hex>") to lowercase hex,
// or "" when malformed (comparisons fail closed). Mirrors hexOf.
func tspHexOf(h string) string {
	s := h
	low := strings.ToLower(s)
	for _, pfx := range []string{"sha256:", "sha384:", "sha512:"} {
		if strings.HasPrefix(low, pfx) {
			s = s[len(pfx):]
			break
		}
	}
	s = strings.ToLower(s)
	if tspHexRe.MatchString(s) && len(s)%2 == 0 && len(s) >= 40 {
		return s
	}
	return ""
}

func tspKeyIDOfSPKI(spkiDer []byte) string {
	sum := sha256.Sum256(spkiDer)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// tspLoadedKey is a pinned TSA key that parsed successfully.
type tspLoadedKey struct {
	pub     crypto.PublicKey
	spkiDer []byte
}

// tspLoadPinnedKey loads one pinned TSA key from a base64/base64url SPKI DER
// string or a PEM string. Returns nil (fail-closed) if it cannot be loaded.
// Mirrors loadPinnedKey.
func tspLoadPinnedKey(pinned string) *tspLoadedKey {
	if pinned == "" {
		return nil
	}
	var der []byte
	if strings.Contains(pinned, "-----BEGIN") {
		block := tspPemDecode(pinned)
		if block == nil {
			return nil
		}
		der = block
	} else {
		cleaned := tspStripWhitespace(pinned)
		if cleaned == "" {
			return nil
		}
		d, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			d, err = base64.RawStdEncoding.DecodeString(cleaned)
		}
		if err != nil {
			d, err = base64.URLEncoding.DecodeString(cleaned)
		}
		if err != nil {
			d, err = base64.RawURLEncoding.DecodeString(cleaned)
		}
		if err != nil {
			return nil
		}
		der = d
	}
	if len(der) == 0 {
		return nil
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil
	}
	// Re-encode to canonical SPKI DER so the fingerprint matches the JS/Python
	// ports (which fingerprint the key's own SPKI export, not the input bytes).
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	return &tspLoadedKey{pub: pub, spkiDer: spki}
}

func tspStripWhitespace(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// tspPemDecode extracts the DER body from the first PEM block, without importing
// encoding/pem specifically for a public key (kept minimal + local).
func tspPemDecode(pem string) []byte {
	begin := strings.Index(pem, "-----BEGIN")
	if begin < 0 {
		return nil
	}
	nl := strings.IndexByte(pem[begin:], '\n')
	if nl < 0 {
		return nil
	}
	rest := pem[begin+nl+1:]
	end := strings.Index(rest, "-----END")
	if end < 0 {
		return nil
	}
	body := tspStripWhitespace(rest[:end])
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil
	}
	return der
}

// tspDerSetHeader encodes a DER SET (0x31) header for a body of the given length.
func tspDerSetHeader(length int) []byte {
	if length < 0x80 {
		return []byte{0x31, byte(length)}
	}
	body := []byte{}
	n := length
	for n > 0 {
		body = append([]byte{byte(n & 0xff)}, body...)
		n >>= 8
	}
	return append([]byte{0x31, byte(0x80 | len(body))}, body...)
}

// tspTstInfo carries the fields extracted from the TSTInfo eContent.
type tspTstInfo struct {
	messageImprintHex string
	genTime           string
}

func tspParseTstInfo(der []byte) (*tspTstInfo, string) {
	seq, err := tspReadTLV(der, 0)
	if err != nil || seq.tag != 0x10 {
		return nil, "unparseable_token"
	}
	kids, err := tspChildren(seq)
	if err != nil || len(kids) < 5 {
		return nil, "unparseable_token"
	}
	mi := kids[2]
	if mi.tag != 0x10 {
		return nil, "unparseable_token"
	}
	miKids, err := tspChildren(mi)
	if err != nil || len(miKids) < 2 {
		return nil, "unparseable_token"
	}
	hashedMessage := miKids[1]
	if hashedMessage.tag != 0x04 {
		return nil, "unparseable_token"
	}
	messageImprintHex := strings.ToLower(hex.EncodeToString(hashedMessage.content()))
	genTime := ""
	for i := 3; i < len(kids); i++ {
		if kids[i].tag == 0x18 || kids[i].tag == 0x17 {
			genTime = tspDecodeGeneralizedTime(kids[i])
			break
		}
	}
	return &tspTstInfo{messageImprintHex: messageImprintHex, genTime: genTime}, ""
}

// tspSignerInfo carries the fields extracted from the single SignerInfo.
type tspSignerInfo struct {
	digestName  string
	signedAttrs *tspNode
	sigAlgOid   string
	signature   []byte
}

func tspParseSignerInfo(node *tspNode) (*tspSignerInfo, string) {
	if node.tag != 0x10 {
		return nil, "unparseable_token"
	}
	kids, err := tspChildren(node)
	if err != nil {
		return nil, "unparseable_token"
	}
	idx := 0
	if idx >= len(kids) || kids[idx].tag != 0x02 {
		return nil, "unparseable_token"
	}
	idx++ // version
	if idx >= len(kids) {
		return nil, "unparseable_token"
	}
	idx++ // sid
	if idx >= len(kids) || kids[idx].tag != 0x10 {
		return nil, "unparseable_token"
	}
	digestAlg := kids[idx]
	idx++
	daKids, err := tspChildren(digestAlg)
	if err != nil || len(daKids) == 0 {
		return nil, "unparseable_token"
	}
	digestAlgOid, err := tspDecodeOID(daKids[0])
	if err != nil {
		return nil, "unparseable_token"
	}
	var signedAttrs *tspNode
	if idx < len(kids) && kids[idx].cls == 2 && kids[idx].tag == 0 && kids[idx].constructed {
		signedAttrs = kids[idx]
		idx++
	}
	if idx >= len(kids) || kids[idx].tag != 0x10 {
		return nil, "unparseable_token"
	}
	sigAlg := kids[idx]
	idx++
	saKids, err := tspChildren(sigAlg)
	if err != nil || len(saKids) == 0 {
		return nil, "unparseable_token"
	}
	sigAlgOid, err := tspDecodeOID(saKids[0])
	if err != nil {
		return nil, "unparseable_token"
	}
	if idx >= len(kids) || kids[idx].tag != 0x04 {
		return nil, "unparseable_token"
	}
	signature := kids[idx].content()
	return &tspSignerInfo{
		digestName:  tspDigestOIDToName[digestAlgOid],
		signedAttrs: signedAttrs,
		sigAlgOid:   sigAlgOid,
		signature:   signature,
	}, ""
}

type tspParsed struct {
	tstInfo     *tspTstInfo
	signerInfo  *tspSignerInfo
	eContentRaw []byte
}

// tspParseToken mirrors parseTimeStampToken.
func tspParseToken(der []byte) (*tspParsed, string) {
	contentInfo, err := tspReadTLV(der, 0)
	if err != nil || contentInfo.tag != 0x10 || !contentInfo.constructed {
		return nil, "unparseable_token"
	}
	ciKids, err := tspChildren(contentInfo)
	if err != nil || len(ciKids) < 2 {
		return nil, "unparseable_token"
	}
	oid, err := tspDecodeOID(ciKids[0])
	if err != nil {
		return nil, "unparseable_token"
	}
	if oid != tspOidSignedData {
		return nil, "not_signed_data"
	}
	explicit0 := ciKids[1]
	if explicit0.cls != 2 || explicit0.tag != 0 || !explicit0.constructed {
		return nil, "unparseable_token"
	}
	sdList, err := tspChildren(explicit0)
	if err != nil || len(sdList) == 0 {
		return nil, "unparseable_token"
	}
	signedData := sdList[0]
	if signedData.tag != 0x10 {
		return nil, "unparseable_token"
	}
	sdKids, err := tspChildren(signedData)
	if err != nil || len(sdKids) < 4 {
		return nil, "unparseable_token"
	}
	encap := sdKids[2]
	var signerInfos *tspNode
	for i := len(sdKids) - 1; i >= 3; i-- {
		if sdKids[i].tag == 0x11 && sdKids[i].cls == 0 {
			signerInfos = sdKids[i]
			break
		}
	}
	if encap.tag != 0x10 {
		return nil, "unparseable_token"
	}
	if signerInfos == nil {
		return nil, "unparseable_token"
	}
	encapKids, err := tspChildren(encap)
	if err != nil || len(encapKids) < 2 {
		return nil, "unparseable_token"
	}
	ctOid, err := tspDecodeOID(encapKids[0])
	if err != nil {
		return nil, "unparseable_token"
	}
	if ctOid != tspOidCtTSTInfo {
		return nil, "not_a_timestamp_token"
	}
	eContentExplicit := encapKids[1]
	if eContentExplicit.cls != 2 || eContentExplicit.tag != 0 {
		return nil, "unparseable_token"
	}
	octetList, err := tspChildren(eContentExplicit)
	if err != nil || len(octetList) == 0 {
		return nil, "unparseable_token"
	}
	octet := octetList[0]
	if octet.tag != 0x04 {
		return nil, "unparseable_token"
	}
	eContentRaw := octet.content()
	tstInfo, terr := tspParseTstInfo(eContentRaw)
	if terr != "" {
		return nil, terr
	}
	siList, err := tspChildren(signerInfos)
	if err != nil {
		return nil, "unparseable_token"
	}
	if len(siList) != 1 {
		return nil, "unsupported_signerinfo_count"
	}
	signerInfo, serr := tspParseSignerInfo(siList[0])
	if serr != "" {
		return nil, serr
	}
	return &tspParsed{tstInfo: tstInfo, signerInfo: signerInfo, eContentRaw: eContentRaw}, ""
}

// tspParseAttributes returns a SET OF Attribute as { oid: [valueNodes...] }.
func tspParseAttributes(setNode *tspNode) (map[string][]*tspNode, error) {
	out := map[string][]*tspNode{}
	kids, err := tspChildren(setNode)
	if err != nil {
		return nil, err
	}
	for _, attr := range kids {
		if attr.tag != 0x10 {
			continue
		}
		aKids, err := tspChildren(attr)
		if err != nil || len(aKids) < 2 {
			continue
		}
		oid, err := tspDecodeOID(aKids[0])
		if err != nil {
			continue
		}
		vals, err := tspChildren(aKids[1])
		if err != nil {
			continue
		}
		out[oid] = vals
	}
	return out, nil
}

func tspHashDigest(name string, b []byte) []byte {
	switch name {
	case "sha256":
		s := sha256.Sum256(b)
		return s[:]
	case "sha384":
		s := sha512.Sum384(b)
		return s[:]
	case "sha512":
		s := sha512.Sum512(b)
		return s[:]
	}
	return nil
}

func tspCryptoHash(name string) crypto.Hash {
	switch name {
	case "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	}
	return 0
}

type tspSigResult struct {
	ok       bool
	tsaKeyID string
	reason   string
}

// tspVerifySignerInfo mirrors verifySignerInfo.
func tspVerifySignerInfo(si *tspSignerInfo, eContentRaw []byte, loadedKeys []*tspLoadedKey) tspSigResult {
	if si.digestName == "" {
		return tspSigResult{reason: "unsupported_digest_algorithm"}
	}
	var signedBytes []byte
	if si.signedAttrs != nil {
		attrs, err := tspParseAttributes(si.signedAttrs)
		if err != nil {
			return tspSigResult{reason: "unparseable_token"}
		}
		ctNodes := attrs[tspOidContentType]
		if len(ctNodes) != 1 {
			return tspSigResult{reason: "missing_content_type_attr"}
		}
		ctOid, err := tspDecodeOID(ctNodes[0])
		if err != nil {
			return tspSigResult{reason: "unparseable_token"}
		}
		if ctOid != tspOidCtTSTInfo {
			return tspSigResult{reason: "content_type_attr_mismatch"}
		}
		mdNodes := attrs[tspOidMessageDigest]
		if len(mdNodes) != 1 || mdNodes[0].tag != 0x04 {
			return tspSigResult{reason: "missing_message_digest_attr"}
		}
		attrDigest := mdNodes[0].content()
		eContentDigest := tspHashDigest(si.digestName, eContentRaw)
		if !tspBytesEqual(attrDigest, eContentDigest) {
			return tspSigResult{reason: "message_digest_attr_mismatch"}
		}
		// Signature input: DER re-encoding of the attributes as an explicit SET
		// (0x31), NOT the [0] IMPLICIT tag (RFC 5652 §5.4).
		attrsBody := si.signedAttrs.raw()[si.signedAttrs.headerLen:]
		signedBytes = append(tspDerSetHeader(len(attrsBody)), attrsBody...)
	} else {
		signedBytes = eContentRaw
	}

	for _, lk := range loadedKeys {
		if tspVerifyOne(lk.pub, si.sigAlgOid, si.digestName, signedBytes, si.signature) {
			return tspSigResult{ok: true, tsaKeyID: tspKeyIDOfSPKI(lk.spkiDer)}
		}
	}
	return tspSigResult{reason: "bad_signature"}
}

// tspVerifyOne verifies the signature under one pinned key, enforcing the same
// signatureAlgorithm/key-type consistency guard as the JS reference.
func tspVerifyOne(pub crypto.PublicKey, sigAlgOid, digestName string, signedBytes, signature []byte) bool {
	ch := tspCryptoHash(digestName)
	if ch == 0 {
		return false
	}
	digest := tspHashDigest(digestName, signedBytes)
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if sigAlgOid != tspOidRSAEncryption {
			return false
		}
		return rsa.VerifyPKCS1v15(key, ch, digest, signature) == nil
	case *ecdsa.PublicKey:
		if sigAlgOid != tspOidECDSASHA256 && sigAlgOid != tspOidECDSASHA384 && sigAlgOid != tspOidECDSASHA512 {
			return false
		}
		return ecdsa.VerifyASN1(key, digest, signature)
	}
	return false
}

func tspBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// VerifyTimestampProof parses + verifies an RFC 3161 TimeStampToken against a
// PINNED TSA key. Byte-for-byte behavioral parity with verifyTimestampProof in
// packages/verify/timestamp-proof.js. FAIL-CLOSED: on any refusal Verified is
// false and Reason carries a distinct string; on success TSAKeyID and GenTime are
// populated. Never panics.
//
// timestampProof: DER TimeStampToken as base64/base64url (or "" for missing).
// expectedDigest: the digest the token MUST timestamp ("sha256:<hex>" or hex).
// pinnedTSAKeys: the caller-supplied trust set (SPKI-DER base64/base64url or PEM).
//
//	The token REFUSES unless its signature verifies under one of these keys.
func VerifyTimestampProof(timestampProof, expectedDigest string, pinnedTSAKeys []string) TimestampProofResult {
	if strings.TrimSpace(timestampProof) == "" {
		return tspRefuse("missing_token")
	}
	wantDigest := tspHexOf(expectedDigest)
	if wantDigest == "" {
		return tspRefuse("missing_or_malformed_expected_digest")
	}
	loadedKeys := []*tspLoadedKey{}
	for _, p := range pinnedTSAKeys {
		if lk := tspLoadPinnedKey(p); lk != nil {
			loadedKeys = append(loadedKeys, lk)
		}
	}
	if len(loadedKeys) == 0 {
		return tspRefuse("unpinned_tsa")
	}

	cleaned := tspStripWhitespace(timestampProof)
	der, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		der, err = base64.RawStdEncoding.DecodeString(cleaned)
	}
	if err != nil {
		der, err = base64.URLEncoding.DecodeString(cleaned)
	}
	if err != nil {
		der, err = base64.RawURLEncoding.DecodeString(cleaned)
	}
	if err != nil || len(der) == 0 {
		return tspRefuse("unparseable_token")
	}

	parsed, perr := tspParseToken(der)
	if perr != "" {
		return tspRefuse(perr)
	}

	if parsed.tstInfo.messageImprintHex != wantDigest {
		return tspRefuse("digest_mismatch")
	}
	if parsed.tstInfo.genTime == "" {
		return tspRefuse("unparseable_token")
	}

	sig := tspVerifySignerInfo(parsed.signerInfo, parsed.eContentRaw, loadedKeys)
	if !sig.ok {
		return tspRefuse(sig.reason)
	}
	return TimestampProofResult{Verified: true, TSAKeyID: sig.tsaKeyID, GenTime: parsed.tstInfo.genTime}
}
