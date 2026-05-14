package scanner

import (
	"fmt"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/python"

	"github.com/1MansiS/qsafe/internal/findings"
)

type language int

const (
	langJava language = iota
	langPython
	langGo
	langC
)

func detectLanguage(ext string) (language, bool) {
	switch strings.ToLower(ext) {
	case ".java":
		return langJava, true
	case ".py":
		return langPython, true
	case ".go":
		return langGo, true
	case ".c", ".h":
		return langC, true
	default:
		return 0, false
	}
}

func langName(lang language) string {
	switch lang {
	case langJava:
		return "java"
	case langPython:
		return "python"
	case langGo:
		return "go"
	case langC:
		return "c"
	default:
		return ""
	}
}

func sitterLang(lang language) *sitter.Language {
	switch lang {
	case langJava:
		return java.GetLanguage()
	case langPython:
		return python.GetLanguage()
	case langGo:
		return golang.GetLanguage()
	case langC:
		return c.GetLanguage()
	default:
		return nil
	}
}

func scanAST(content []byte, path string, lang language) ([]findings.Finding, error) {
	parser := sitter.NewParser()
	parser.SetLanguage(sitterLang(lang))
	tree := parser.Parse(nil, content)

	var result []findings.Finding
	walkNode(tree.RootNode(), content, func(n *sitter.Node) {
		var found []findings.Finding
		switch lang {
		case langJava:
			found = matchJava(n, content, path)
		case langPython:
			found = matchPython(n, content, path)
		case langGo:
			found = matchGo(n, content, path)
		case langC:
			found = matchC(n, content, path)
		}
		result = append(result, found...)
	})

	return result, nil
}

func walkNode(n *sitter.Node, content []byte, fn func(*sitter.Node)) {
	if n == nil {
		return
	}
	fn(n)
	for i := 0; i < int(n.ChildCount()); i++ {
		walkNode(n.Child(i), content, fn)
	}
}

// ── Java ─────────────────────────────────────────────────────────────────────

func matchJava(n *sitter.Node, content []byte, path string) []findings.Finding {
	line := int(n.StartPoint().Row) + 1
	switch n.Type() {
	case "method_invocation":
		return matchJavaMethodInvocation(n, content, path, line)
	case "object_creation_expression":
		return matchJavaObjectCreation(n, content, path, line)
	}
	return nil
}

func matchJavaMethodInvocation(n *sitter.Node, content []byte, path string, line int) []findings.Finding {
	nameNode := n.ChildByFieldName("name")
	if nameNode == nil || nameNode.Content(content) != "getInstance" {
		return nil
	}

	className := ""
	if obj := n.ChildByFieldName("object"); obj != nil {
		className = obj.Content(content)
	}

	argsNode := n.ChildByFieldName("arguments")
	if argsNode == nil {
		return nil
	}

	var algStr string
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child.Type() == "string_literal" {
			algStr = strings.Trim(child.Content(content), `"`)
			break
		}
	}
	if algStr == "" {
		return nil
	}

	return javaAlgorithmToFinding(algStr, className, path, line)
}

func matchJavaObjectCreation(n *sitter.Node, content []byte, path string, line int) []findings.Finding {
	typeNode := n.ChildByFieldName("type")
	if typeNode == nil || typeNode.Content(content) != "RSAKeyGenParameterSpec" {
		return nil
	}
	argsNode := n.ChildByFieldName("arguments")
	if argsNode == nil || argsNode.NamedChildCount() < 1 {
		return nil
	}
	first := argsNode.NamedChild(0)
	if first.Type() != "decimal_integer_literal" {
		return nil
	}
	size, err := strconv.Atoi(first.Content(content))
	if err != nil || size <= 0 || size >= 3072 {
		return nil
	}
	return []findings.Finding{{
		Primitive: "RSA",
		Usage:     "key_size_insufficient",
		File:      path,
		Line:      line,
		Severity:  findings.SeverityHigh,
		Detail:    fmt.Sprintf("key size %d is below the 3072-bit minimum (CNSA 2.0)", size),
	}}
}

func javaAlgorithmToFinding(alg, className, path string, line int) []findings.Finding {
	upper := strings.ToUpper(alg)

	switch {
	case strings.HasPrefix(upper, "RSA") || strings.HasSuffix(upper, "WITHRSA"):
		usage := inferJavaUsage(className, "encryption")
		if strings.HasSuffix(upper, "WITHRSA") {
			usage = "signing"
		}
		return []findings.Finding{{Primitive: "RSA", Usage: usage, File: path, Line: line, Severity: findings.SeverityHigh}}

	case upper == "ECDH":
		return []findings.Finding{{Primitive: "ECDH", Usage: "key_agreement", File: path, Line: line, Severity: findings.SeverityHigh}}

	case strings.Contains(upper, "ECDSA") || strings.Contains(upper, "WITHECDSA"):
		return []findings.Finding{{Primitive: "ECDSA", Usage: "signing", File: path, Line: line, Severity: findings.SeverityHigh}}

	case upper == "EC":
		return []findings.Finding{{Primitive: "ECDH", Usage: "key_generation", File: path, Line: line, Severity: findings.SeverityHigh}}

	case upper == "AES" || strings.HasPrefix(upper, "AES/ECB"):
		return []findings.Finding{{Primitive: "AES-ECB", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityMedium}}

	case strings.HasPrefix(upper, "DESEDE") || strings.HasPrefix(upper, "3DES") || strings.HasPrefix(upper, "TRIPLEDES"):
		return []findings.Finding{{Primitive: "3DES", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityHigh}}

	case upper == "DES" || strings.HasPrefix(upper, "DES/"):
		return []findings.Finding{{Primitive: "DES", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityHigh}}

	case upper == "RC4" || upper == "ARCFOUR":
		return []findings.Finding{{Primitive: "RC4", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityHigh}}

	case upper == "MD5" || strings.Contains(upper, "MD5WITH") || strings.Contains(upper, "WITHMD5"):
		usage := "hashing"
		if className == "Signature" || className == "Mac" || strings.Contains(upper, "WITH") {
			usage = "signing"
		}
		return []findings.Finding{{Primitive: "MD5", Usage: usage, File: path, Line: line, Severity: findings.SeverityMedium}}

	case upper == "SHA-1" || upper == "SHA1" || strings.Contains(upper, "SHA1WITH") || strings.Contains(upper, "WITHSHA1") || strings.Contains(upper, "SHA-1WITH"):
		usage := "hashing"
		if className == "Signature" || className == "Mac" || strings.Contains(upper, "WITH") {
			usage = "signing"
		}
		return []findings.Finding{{Primitive: "SHA-1", Usage: usage, File: path, Line: line, Severity: findings.SeverityMedium}}
	}
	return nil
}

func inferJavaUsage(className, defaultUsage string) string {
	switch className {
	case "KeyPairGenerator", "KeyFactory":
		return "key_generation"
	case "KeyAgreement":
		return "key_agreement"
	case "Signature":
		return "signing"
	case "MessageDigest":
		return "hashing"
	default:
		return defaultUsage
	}
}

// ── Python ───────────────────────────────────────────────────────────────────

func matchPython(n *sitter.Node, content []byte, path string) []findings.Finding {
	line := int(n.StartPoint().Row) + 1

	switch n.Type() {
	case "call":
		fnNode := n.ChildByFieldName("function")
		if fnNode == nil {
			return nil
		}
		fnText := fnNode.Content(content)
		return matchPythonCall(fnText, n, content, path, line)

	case "attribute":
		attrNode := n.ChildByFieldName("attribute")
		if attrNode == nil {
			return nil
		}
		attrText := attrNode.Content(content)
		objNode := n.ChildByFieldName("object")
		objText := ""
		if objNode != nil {
			objText = objNode.Content(content)
		}
		return matchPythonAttribute(attrText, objText, path, line)
	}
	return nil
}

func matchPythonCall(fn string, n *sitter.Node, content []byte, path string, line int) []findings.Finding {
	switch {
	case fn == "RSA.generate" || fn == "rsa.generate_private_key":
		size := extractPythonRSAKeySize(fn, n, content)
		f := findings.Finding{Primitive: "RSA", Usage: "key_generation", File: path, Line: line, Severity: findings.SeverityHigh}
		if size > 0 && size < 3072 {
			f.Detail = fmt.Sprintf("key size %d is below the 3072-bit minimum (CNSA 2.0)", size)
		}
		return []findings.Finding{f}

	case fn == "ec.generate_private_key" || fn == "ECC.generate":
		return []findings.Finding{{Primitive: "ECDH", Usage: "key_generation", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fn == "ecdsa.SigningKey.generate":
		return []findings.Finding{{Primitive: "ECDSA", Usage: "key_generation", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fn == "DES3.new":
		return []findings.Finding{{Primitive: "3DES", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fn == "DES.new":
		return []findings.Finding{{Primitive: "DES", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fn == "ARC4.new":
		return []findings.Finding{{Primitive: "RC4", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fn == "hashlib.md5" || fn == "MD5.new":
		return []findings.Finding{{Primitive: "MD5", Usage: "hashing", File: path, Line: line, Severity: findings.SeverityMedium}}

	case fn == "hashlib.sha1" || fn == "SHA1.new" || fn == "SHA.new":
		return []findings.Finding{{Primitive: "SHA-1", Usage: "hashing", File: path, Line: line, Severity: findings.SeverityMedium}}

	case fn == "hashes.MD5":
		return []findings.Finding{{Primitive: "MD5", Usage: "hashing", File: path, Line: line, Severity: findings.SeverityMedium}}

	case fn == "hashes.SHA1":
		return []findings.Finding{{Primitive: "SHA-1", Usage: "hashing", File: path, Line: line, Severity: findings.SeverityMedium}}

	case fn == "modes.ECB":
		return []findings.Finding{{Primitive: "AES-ECB", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityMedium}}
	}
	return nil
}

func matchPythonAttribute(attr, obj, path string, line int) []findings.Finding {
	switch attr {
	case "MODE_ECB":
		return []findings.Finding{{Primitive: "AES-ECB", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityMedium}}
	case "ECB":
		if obj == "modes" || strings.HasSuffix(obj, ".modes") {
			return []findings.Finding{{Primitive: "AES-ECB", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityMedium}}
		}
	}
	return nil
}

// extractPythonRSAKeySize tries to read the key size literal from RSA.generate(size) or
// rsa.generate_private_key(..., key_size=size, ...).
func extractPythonRSAKeySize(fn string, n *sitter.Node, content []byte) int {
	argsNode := n.ChildByFieldName("arguments")
	if argsNode == nil {
		return 0
	}
	if fn == "RSA.generate" {
		// First positional arg
		if argsNode.NamedChildCount() >= 1 {
			first := argsNode.NamedChild(0)
			if first.Type() == "integer" {
				size, _ := strconv.Atoi(first.Content(content))
				return size
			}
		}
	}
	if fn == "rsa.generate_private_key" {
		// keyword arg key_size=N
		for i := 0; i < int(argsNode.NamedChildCount()); i++ {
			kw := argsNode.NamedChild(i)
			if kw.Type() == "keyword_argument" {
				nameNode := kw.ChildByFieldName("name")
				valNode := kw.ChildByFieldName("value")
				if nameNode != nil && nameNode.Content(content) == "key_size" && valNode != nil {
					if valNode.Type() == "integer" {
						size, _ := strconv.Atoi(valNode.Content(content))
						return size
					}
				}
			}
		}
	}
	return 0
}

// ── Go ───────────────────────────────────────────────────────────────────────

func matchGo(n *sitter.Node, content []byte, path string) []findings.Finding {
	if n.Type() != "call_expression" {
		return nil
	}
	fnNode := n.ChildByFieldName("function")
	if fnNode == nil {
		return nil
	}
	fnText := fnNode.Content(content)
	line := int(n.StartPoint().Row) + 1

	switch {
	case fnText == "rsa.GenerateKey":
		size := extractGoRSAKeySize(n, content)
		f := findings.Finding{Primitive: "RSA", Usage: "key_generation", File: path, Line: line, Severity: findings.SeverityHigh}
		if size > 0 && size < 3072 {
			f.Detail = fmt.Sprintf("key size %d is below the 3072-bit minimum (CNSA 2.0)", size)
		}
		return []findings.Finding{f}

	case fnText == "rsa.EncryptPKCS1v15" || fnText == "rsa.EncryptOAEP" || fnText == "rsa.DecryptPKCS1v15" || fnText == "rsa.DecryptOAEP":
		return []findings.Finding{{Primitive: "RSA", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fnText == "rsa.SignPKCS1v15" || fnText == "rsa.SignPSS" || fnText == "rsa.VerifyPKCS1v15" || fnText == "rsa.VerifyPSS":
		return []findings.Finding{{Primitive: "RSA", Usage: "signing", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fnText == "ecdsa.GenerateKey":
		return []findings.Finding{{Primitive: "ECDSA", Usage: "key_generation", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fnText == "ecdsa.Sign" || fnText == "ecdsa.Verify" || fnText == "ecdsa.SignASN1" || fnText == "ecdsa.VerifyASN1":
		return []findings.Finding{{Primitive: "ECDSA", Usage: "signing", File: path, Line: line, Severity: findings.SeverityHigh}}

	case strings.HasPrefix(fnText, "ecdh."):
		return []findings.Finding{{Primitive: "ECDH", Usage: "key_agreement", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fnText == "des.NewTripleDESCipher":
		return []findings.Finding{{Primitive: "3DES", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fnText == "des.NewCipher":
		return []findings.Finding{{Primitive: "DES", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fnText == "rc4.NewCipher":
		return []findings.Finding{{Primitive: "RC4", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fnText == "md5.New" || fnText == "md5.Sum":
		return []findings.Finding{{Primitive: "MD5", Usage: "hashing", File: path, Line: line, Severity: findings.SeverityMedium}}

	case fnText == "sha1.New" || fnText == "sha1.Sum":
		return []findings.Finding{{Primitive: "SHA-1", Usage: "hashing", File: path, Line: line, Severity: findings.SeverityMedium}}
	}
	return nil
}

// extractGoRSAKeySize reads the bits literal from rsa.GenerateKey(rand, bits).
func extractGoRSAKeySize(n *sitter.Node, content []byte) int {
	argsNode := n.ChildByFieldName("arguments")
	if argsNode == nil || argsNode.NamedChildCount() < 2 {
		return 0
	}
	// Second named child is the key size
	sizeNode := argsNode.NamedChild(1)
	if sizeNode.Type() == "int_literal" {
		size, _ := strconv.Atoi(sizeNode.Content(content))
		return size
	}
	return 0
}

// ── C ────────────────────────────────────────────────────────────────────────

func matchC(n *sitter.Node, content []byte, path string) []findings.Finding {
	if n.Type() != "call_expression" {
		return nil
	}
	fnNode := n.ChildByFieldName("function")
	if fnNode == nil {
		return nil
	}
	fnText := fnNode.Content(content)
	line := int(n.StartPoint().Row) + 1

	switch {
	case strings.HasPrefix(fnText, "RSA_"):
		return []findings.Finding{{Primitive: "RSA", Usage: inferCRSAUsage(fnText), File: path, Line: line, Severity: findings.SeverityHigh}}

	case fnText == "ECDH_compute_key" || strings.HasPrefix(fnText, "ECDH_"):
		return []findings.Finding{{Primitive: "ECDH", Usage: "key_agreement", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fnText == "ECDSA_sign" || fnText == "ECDSA_verify" || strings.HasPrefix(fnText, "ECDSA_"):
		return []findings.Finding{{Primitive: "ECDSA", Usage: "signing", File: path, Line: line, Severity: findings.SeverityHigh}}

	case strings.HasPrefix(fnText, "EVP_des") || strings.HasPrefix(fnText, "DES_"):
		return []findings.Finding{{Primitive: "DES", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fnText == "RC4" || strings.HasPrefix(fnText, "RC4_"):
		return []findings.Finding{{Primitive: "RC4", Usage: "encryption", File: path, Line: line, Severity: findings.SeverityHigh}}

	case fnText == "MD5" || strings.HasPrefix(fnText, "MD5_"):
		return []findings.Finding{{Primitive: "MD5", Usage: "hashing", File: path, Line: line, Severity: findings.SeverityMedium}}

	case fnText == "SHA1" || strings.HasPrefix(fnText, "SHA1_"):
		return []findings.Finding{{Primitive: "SHA-1", Usage: "hashing", File: path, Line: line, Severity: findings.SeverityMedium}}
	}
	return nil
}

func inferCRSAUsage(fn string) string {
	fn = strings.ToLower(fn)
	switch {
	case strings.Contains(fn, "generate") || strings.Contains(fn, "new"):
		return "key_generation"
	case strings.Contains(fn, "encrypt") || strings.Contains(fn, "public"):
		return "encryption"
	case strings.Contains(fn, "sign"):
		return "signing"
	default:
		return "encryption"
	}
}
