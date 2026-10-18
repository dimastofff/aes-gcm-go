# Contributing

Keep changes focused and describe the problem, resulting behavior, and validation
in the pull request. Report suspected vulnerabilities through the process in
[SECURITY.md](SECURITY.md).

## Compatibility

The package and ordinary tests must compile with Go 1.13. Preserve the public
`Cipher` interface, sentinel errors, and v1 wire format:
`nonce[12] || ciphertext || tag[16]`. Add a regression test when changing behavior.

Use a currently supported Go release for development. Native fuzz tests require
Go 1.18 or later; the `cipher.NewGCMWithRandomNonce` interoperability test requires
Go 1.24 or later. Version-specific test files use both `//go:build` and legacy
`// +build` constraints so older toolchains can skip them. Keep those constraints
when editing or adding such files.

## Checks

Run these commands from the repository root:

```sh
gofmt -l .
go test ./...
go vet ./...
go test -race ./...
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

`gofmt -l .` should produce no output; format changed files with `gofmt -w` before
submitting. Race detection requires a supported platform and, where required, a
C compiler. Do not commit generated coverage reports.

Run each fuzz target separately on Go 1.18 or later:

```sh
go test -run '^$' -fuzz '^FuzzDecrypt$' -fuzztime=30s -parallel=2 .
go test -run '^$' -fuzz '^FuzzRoundTrip$' -fuzztime=30s -parallel=2 .
```

These bounded runs are a quick check; use a longer `-fuzztime` when investigating a
failure. Keep reproducible failure inputs as regression cases.

Check known vulnerabilities with a supported Go toolchain:

```sh
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

Pull-request and push checks run tests on `stable` and `oldstable`, check Go 1.13
compatibility separately, and check formatting, vet, races, coverage, and bounded
fuzzing. Weekly or manually triggered maintenance runs longer fuzz checks and a
pinned `govulncheck` release with a current toolchain. Update the version above
alongside the workflow when upgrading that tool.

## Benchmarks

```sh
go test -run '^$' -bench=. -benchmem ./...
```

Report the Go version, operating system, architecture, CPU, and input sizes when
comparing results. Allocation counts and bytes per operation measure different
things; a fixed allocation count does not imply constant memory use. Benchmarks
are also available through the manually triggered benchmark workflow and are not
a performance pass/fail gate.
