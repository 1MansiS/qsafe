# research/

Historical design exploration, not the active scanning engine.

This directory documents why `internal/scanner` uses `go/ast` + `go/types`
rather than `tree-sitter-go`: a working prototype was built here and
validated against 5 real-world Go repositories before concluding the two
approaches tied on capability (zero mechanism-level gaps either way), at
which point `go/ast` won on deployment/contributor friction (no cgo, no
C toolchain needed, better fit for MCP-server distribution as a single
native binary).

It also contains the original `go/types` interface-dispatch heuristic
prototype (`internal/detect/go_types.go`) — that one *did* graduate, into
`internal/scanner/interface_dispatch_go.go`.

Kept committed deliberately, as the evidence trail for that decision —
see the project's design notes for the full before/after data. Not
wired into any build, not a dependency of anything under `internal/` or
`cmd/`; isolated as its own Go module (`research/go.mod`) specifically so
its dependencies (including cgo) never touch the real module.
