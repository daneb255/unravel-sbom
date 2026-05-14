# Security Policy

## Reporting Security Vulnerabilities

**⚠️ DO NOT file security vulnerabilities as public issues.**

If you discover a security vulnerability in unravel-sbom, please report it responsibly by emailing the maintainer directly. This allows us to address the issue before it becomes public.

### How to Report

1. Email the maintainer at `d@bitzer.dev`
2. Include:
   - Description of the vulnerability
   - Steps to reproduce (if applicable)
   - Potential impact
   - Suggested fix (if you have one)
   - Your contact information for follow-up

3. **Do not:**
   - Post details publicly
   - Create a public GitHub issue
   - File a CVE independently
   - Disclose the vulnerability on social media

### Response Timeline

- We will acknowledge receipt within 48 hours
- We will provide an initial assessment within 5 business days
- We will work toward a fix and coordinated disclosure
- Credit will be given to reporters (unless you prefer anonymity)

## Vulnerability in Scanned Packages

If you discover that unravel-sbom produces incorrect or misleading SBOM output for a known-malicious package:

- Report it directly to [OSV.dev](https://osv.dev/)
- Report it to the [OSSF Malicious Packages](https://github.com/ossf/malicious-packages) project
- This helps the entire ecosystem benefit from improved detection

## Security Considerations for Users

### Input Handling

- unravel-sbom parses files from arbitrary project directories — only scan directories you trust
- XML parsing (`package.xml`) uses `defusedxml` to prevent entity expansion and XXE attacks
- Dependency-Track URLs are validated to `http://` or `https://` schemes before any network request is made

### Dependency-Track Integration

- Always use HTTPS for your Dependency-Track instance (`--dtrack-url https://...`)
- Treat your API key (`--dtrack-key`) as a secret — pass it via `$DTRACK_API_KEY` rather than inline on the command line
- Restrict the API key to the minimum required permissions (`BOM_UPLOAD`)

### CI/CD Pipelines

- Store `DTRACK_API_KEY` as an encrypted secret in your CI system, never in plaintext
- Review generated SBOM files before committing them — they may contain internal package names or paths

### Dependencies

- Keep unravel-sbom and its dependencies up to date
- The project runs Bandit (static analysis) and Safety (dependency CVE scan) in CI on every push and weekly via a scheduled workflow
- Use `pip-audit` or `safety check` locally to scan for known vulnerabilities in installed packages

## Known Security Limitations

1. **No network isolation:** When using `--dtrack-url`, unravel-sbom makes outbound HTTP requests to the configured URL. Ensure the URL is trusted.
2. **File-system access:** The scanner reads every file it matches in the target directory. Do not run it on untrusted or adversarially constructed directories without sandboxing.
3. **SBOM accuracy:** Generated SBOMs reflect what is declared in manifest files, not what is actually installed. A compromised or tampered manifest will produce an inaccurate SBOM.

## Security Roadmap

- [ ] `pip-audit` integration as an optional deep-scan mode
- [ ] SBOM signing support (Sigstore / cosign)
- [ ] Structured security advisory format (CSAF / VEX)
- [ ] Sandboxed scanning mode for untrusted directories

## Acknowledgments

We are grateful to security researchers and the open-source community for helping keep unravel-sbom and the broader ecosystem secure.

## See Also

- [README.md](README.md) — Project overview
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Community standards
- [CONTRIBUTING.md](CONTRIBUTING.md) — Developer guidelines
