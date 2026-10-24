# Third-party notices

Wardline (© 2026 Undrocs) is proprietary software distributed under the terms
in [LICENSE](LICENSE). The components below are included in, or required to
build, the distributed software and remain under their own licenses.

## Go modules

### github.com/goccy/go-yaml v1.19.2

- License: MIT
- Copyright © 2019 Masaaki Goshima
- Used for: parsing `.wardline.yaml`, GitHub Actions workflows, Docker Compose
  files and YAML application configuration. The library is also used to obtain
  line and column positions for findings.
- Source: https://github.com/goccy/go-yaml

```
MIT License

Copyright (c) 2019 Masaaki Goshima

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The complete license text is also present in the module cache at
`$(go env GOMODCACHE)/github.com/goccy/go-yaml@v1.19.2/LICENSE` for any build
that downloads the module.

## Go standard library

Wardline links the Go standard library, which is distributed under the Go
project's BSD-style license and is covered by the Go distribution's own
`LICENSE` file provided with the toolchain.

## External services and data

- **OSV.dev** (<https://osv.dev>) is queried over HTTPS for published
  vulnerability data. No OSV data is bundled or redistributed with Wardline.
  Use of the API is subject to Google's terms for the OSV service.
- **Advisory data** returned by OSV originates from GitHub Advisory Database,
  the National Vulnerability Database and ecosystem maintainers. Finding text
  quotes advisory summaries verbatim (sanitised and truncated) and attributes
  the advisory ID.
- Wardline does **not** embed the Gitleaks engine, its rule definitions, or any
  other third-party detection rule set. Secret patterns were authored for this
  project.

## Runtime dependencies

None beyond the operating system. Wardline is a single static binary and does
not invoke `git`, Docker, package managers, shells or any other external
program during a scan.

## Maintaining this file

Any new module, vendored code, embedded data set or external service must be
added here, together with its license, in the same pull request that introduces
it. Dependencies with copyleft licenses, unknown licenses or licenses
incompatible with closed-source distribution are not accepted.
