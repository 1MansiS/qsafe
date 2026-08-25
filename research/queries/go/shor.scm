; Shor-broken Go crypto call patterns. Each pattern fully encodes one
; finding: package identifier and function name are matched literally, so a
; match *is* the finding — the capture name carries primitive + usage
; directly (@finding.<primitive>.<usage>), read off by the Go side with no
; lookup table involved.
;
; Known, accepted limitation for this spike: literal package-name matching
; misses aliased imports (`import cr "crypto/rsa"` then `cr.GenerateKey(...)`).
; Real-world crypto imports are rarely aliased; revisit only if repo data
; shows this actually matters.

(call_expression
  function: (selector_expression
    operand: (identifier) @_pkg (#eq? @_pkg "rsa")
    field: (field_identifier) @_fn (#eq? @_fn "GenerateKey"))) @finding.RSA.key_generation

(call_expression
  function: (selector_expression
    operand: (identifier) @_pkg (#eq? @_pkg "rsa")
    field: (field_identifier) @_fn (#match? @_fn "^(SignPKCS1v15|SignPSS)$"))) @finding.RSA.signing

(call_expression
  function: (selector_expression
    operand: (identifier) @_pkg (#eq? @_pkg "rsa")
    field: (field_identifier) @_fn (#match? @_fn "^(VerifyPKCS1v15|VerifyPSS)$"))) @finding.RSA.signing

(call_expression
  function: (selector_expression
    operand: (identifier) @_pkg (#eq? @_pkg "rsa")
    field: (field_identifier) @_fn (#match? @_fn "^(EncryptPKCS1v15|EncryptOAEP|DecryptPKCS1v15|DecryptOAEP)$"))) @finding.RSA.encryption

(call_expression
  function: (selector_expression
    operand: (identifier) @_pkg (#eq? @_pkg "ecdsa")
    field: (field_identifier) @_fn (#eq? @_fn "GenerateKey"))) @finding.ECDSA.key_generation

(call_expression
  function: (selector_expression
    operand: (identifier) @_pkg (#eq? @_pkg "ecdsa")
    field: (field_identifier) @_fn (#match? @_fn "^(Sign|SignASN1)$"))) @finding.ECDSA.signing

(call_expression
  function: (selector_expression
    operand: (identifier) @_pkg (#eq? @_pkg "ecdsa")
    field: (field_identifier) @_fn (#match? @_fn "^(Verify|VerifyASN1)$"))) @finding.ECDSA.signing

(call_expression
  function: (selector_expression
    operand: (identifier) @_pkg (#eq? @_pkg "elliptic")
    field: (field_identifier) @_fn (#match? @_fn "^(GenerateKey|P256|P384|P521|P224)$"))) @finding.ECC.key_generation
