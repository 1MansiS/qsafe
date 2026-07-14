#!/usr/bin/env python3
"""qsafe Python crypto scanner — driven by the built-in ast module.
Accepts a single .py file path as argv[1], prints JSON findings to stdout.
"""
import ast
import json
import sys

# (module, name) → (primitive, usage)
#
# For `import X`:              module='X',    name=None (stored as X's own name)
# For `from M import N`:       module='M',    name='N'
# For `from M import N as Z`:  module='M',    name='N' (alias Z maps to this)
#
# Lookup strategy for a Call node:
#   X(...)           → look up (imports[X].module, imports[X].name)
#   X.method(...)    → look up (imports[X].module + '.' + imports[X].name, method)
#                      then fall back to (imports[X].module, method)
CRYPTO_PATTERNS = {
    # cryptography.io — asymmetric RSA
    ("cryptography.hazmat.primitives.asymmetric.rsa", "generate_private_key"): ("RSA", "key_generation"),
    ("cryptography.hazmat.primitives.asymmetric.rsa", "RSAPublicNumbers"):      ("RSA", "key_generation"),
    ("cryptography.hazmat.primitives.asymmetric.rsa", "RSAPrivateNumbers"):     ("RSA", "key_generation"),
    # cryptography.io — asymmetric EC
    ("cryptography.hazmat.primitives.asymmetric.ec", "generate_private_key"):   ("ECDSA/ECDH", "key_generation"),
    ("cryptography.hazmat.primitives.asymmetric.ec", "derive_private_key"):     ("ECDSA/ECDH", "key_generation"),
    ("cryptography.hazmat.primitives.asymmetric.ec", "ECDSA"):                  ("ECDSA",      "signing"),
    ("cryptography.hazmat.primitives.asymmetric.ec", "ECDH"):                   ("ECDH",       "key_agreement"),
    ("cryptography.hazmat.primitives.asymmetric.ec", "SECP256R1"):              ("ECC",        "key_generation"),
    ("cryptography.hazmat.primitives.asymmetric.ec", "SECP384R1"):              ("ECC",        "key_generation"),
    ("cryptography.hazmat.primitives.asymmetric.ec", "SECP521R1"):              ("ECC",        "key_generation"),
    # cryptography.io — hashes
    ("cryptography.hazmat.primitives.hashes", "MD5"):  ("MD5",   "hashing"),
    ("cryptography.hazmat.primitives.hashes", "SHA1"): ("SHA-1", "hashing"),
    # cryptography.io — cipher algorithms
    ("cryptography.hazmat.primitives.ciphers.algorithms", "TripleDES"): ("3DES",     "encryption"),
    ("cryptography.hazmat.primitives.ciphers.algorithms", "ARC4"):      ("RC4",      "encryption"),
    ("cryptography.hazmat.primitives.ciphers.algorithms", "Blowfish"):  ("Blowfish", "encryption"),
    # cryptography.io — modes
    ("cryptography.hazmat.primitives.ciphers.modes", "ECB"): ("AES-ECB", "encryption"),
    # PyCryptodome — direct imports
    ("Crypto.PublicKey", "RSA"): ("RSA",  "key_generation"),
    ("Crypto.PublicKey", "DSA"): ("DSA",  "signing"),
    ("Crypto.Cipher",    "DES3"):     ("3DES",     "encryption"),
    ("Crypto.Cipher",    "DES"):      ("DES",      "encryption"),
    ("Crypto.Cipher",    "ARC4"):     ("RC4",      "encryption"),
    ("Crypto.Cipher",    "Blowfish"): ("Blowfish", "encryption"),
    ("Crypto.Hash",      "MD5"):  ("MD5",   "hashing"),
    ("Crypto.Hash",      "SHA"):  ("SHA-1", "hashing"),
    ("Crypto.Hash",      "SHA1"): ("SHA-1", "hashing"),
    # PyCryptodome — method calls on imported objects
    ("Crypto.Cipher.DES3",     "new"):       ("3DES", "encryption"),
    ("Crypto.Cipher.DES",      "new"):       ("DES",  "encryption"),
    ("Crypto.Cipher.ARC4",     "new"):       ("RC4",  "encryption"),
    ("Crypto.PublicKey.RSA",   "generate"):  ("RSA",  "key_generation"),
    ("Crypto.PublicKey.RSA",   "import_key"):("RSA",  "key_generation"),
    # ecdsa library
    ("ecdsa", "SigningKey"):   ("ECDSA", "signing"),
    ("ecdsa", "VerifyingKey"): ("ECDSA", "signing"),
    # hashlib
    ("hashlib", "md5"):  ("MD5",   "hashing"),
    ("hashlib", "sha1"): ("SHA-1", "hashing"),
}

SEVERITY = {
    "RSA": "HIGH", "ECDSA": "HIGH", "ECDSA/ECDH": "HIGH",
    "ECDH": "HIGH", "ECC": "HIGH", "DSA": "HIGH",
    "3DES": "HIGH", "DES": "HIGH", "RC4": "HIGH", "Blowfish": "HIGH",
    "MD5": "MEDIUM", "SHA-1": "MEDIUM", "AES-ECB": "MEDIUM",
}


class CryptoVisitor(ast.NodeVisitor):
    def __init__(self, filepath):
        self.filepath = filepath
        self.findings = []
        # alias → (module, symbol)
        #   import hashlib          → {'hashlib': ('hashlib', None)}
        #   from X import Y         → {'Y': ('X', 'Y')}
        #   from X import Y as Z    → {'Z': ('X', 'Y')}
        self.imports = {}

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            self.imports[local] = (alias.name, None)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.imports[local] = (mod, alias.name)
        self.generic_visit(node)

    def _match(self, module, name):
        return CRYPTO_PATTERNS.get((module, name))

    def visit_Call(self, node):
        func = node.func
        result = None

        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            # Pattern: X.method(...)
            alias, method = func.value.id, func.attr
            if alias in self.imports:
                mod, sym = self.imports[alias]
                # Try (mod.sym, method) — e.g. DES3.new(), RSA.generate()
                if sym:
                    result = self._match(f"{mod}.{sym}", method)
                # Try (mod.sym, method) with full chain — e.g. ec.generate_private_key()
                if not result:
                    full = f"{mod}.{sym}" if sym else mod
                    result = self._match(full, method)
                # Try bare (mod, method) — e.g. hashlib.md5()
                if not result:
                    result = self._match(mod, method)

        elif isinstance(func, ast.Name):
            # Pattern: X(...) — direct constructor / function call
            alias = func.id
            if alias in self.imports:
                mod, sym = self.imports[alias]
                result = self._match(mod, sym or alias)

        if result:
            primitive, usage = result
            self.findings.append({
                "primitive": primitive,
                "usage":     usage,
                "file":      self.filepath,
                "line":      node.lineno,
                "severity":  SEVERITY.get(primitive, "MEDIUM"),
            })

        self.generic_visit(node)


def scan_file(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            source = f.read()
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return []
    v = CryptoVisitor(path)
    v.visit(tree)
    return v.findings


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: pyast.py <file.py>", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(scan_file(sys.argv[1])))
