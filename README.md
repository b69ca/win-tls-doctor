# win-tls-doctor

Diagnose direct HTTPS DNS, TCP, TLS, certificate, and proxy-configuration problems.

A read-only C# / .NET 10 CLI for Windows 11 and Windows Server 2022/2025. No third-party runtime packages. Live collection uses .NET and Windows APIs; no PowerShell collector is required.

## Run

Download `win-tls-doctor-win-x64` from a successful [GitHub Actions run](https://github.com/b69ca/win-tls-doctor/actions), extract the artifact, and run the executable from a terminal. The standalone artifact includes its .NET runtime. These initial binaries are unsigned; verify their source and CI provenance according to your normal software policy.

```powershell
.\win-tls-doctor.exe --url https://example.com
.\win-tls-doctor.exe --url https://example.com --json > report.json
.\win-tls-doctor.exe --input report.json --json
```

Or build from source with the [.NET 10 SDK](https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/overview):

```powershell
dotnet run --project WinTlsDoctor.csproj -- --url https://example.com
dotnet publish WinTlsDoctor.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/win-x64
```

The JSON output contains the evidence and can be replayed with `--input` on Windows or Linux. Live collection is Windows-only at the CLI boundary. A successful report can contain warnings or errors describing the diagnosed system; it is not a clean bill of health.

## Options

```text
--url HTTPS_URL (required, no embedded credentials)
--timeout N (1–60 seconds, default 15; shared DNS/TCP/TLS budget)
--revocation online|offline|none (default online)
--json          Full versioned JSON report
--input FILE    Analyze saved evidence without live collection
--help          Usage
```

`--input` cannot be combined with live collection options. Unknown and duplicate flags are rejected. Snapshots must match this tool and schema version 1, contain evidence and issues, and be no larger than 8 MiB. `--help` performs no collection. Ctrl-C cancels an active collection.

Exit codes: **0** report produced, including findings or partial evidence; **2** argument/snapshot error; **3** collection failed; **4** live collection attempted outside Windows; **130** cancelled. Automations must inspect `status`, `issues`, and finding severity rather than treating exit 0 as healthy. CLI errors go to stderr; `--json` runtime collection failures emit a `status: failed` envelope.

## Evidence and findings

Uses .NET DNS, a direct TCP connection, and SslStream with OS-selected TLS protocols. The certificate callback records policy errors and accepts the certificate only when the platform reports no errors. Online revocation checks may contact certificate-authority endpoints. Certificate subject, issuer, validity, SAN text, SHA-256 fingerprint, and chain status are included when observed. URL paths, queries, and fragments are not sent or included in the target report.

TCP failures and TLS authentication failures remain separate. Validation is always enforced. --revocation none only changes revocation checking and generates an explicit warning; hostname, validity, and chain trust checks remain enabled.

No HTTP request, login, client-certificate selection, PAC execution, proxy tunnel, or application authentication is attempted. The proxy inventory includes current-user Internet Settings and the presence of HTTP(S)_PROXY environment variables; it does not establish WinHTTP settings, automatic discovery, effective policy, or app-specific configuration. Proxy credentials are redacted and PAC URLs are not recorded. A successful direct TLS handshake does not establish application health.

Text reports show the main facts and actionable findings. JSON includes `schemaVersion`, `tool`, `version`, `collectedAtUtc`, `analyzedAtUtc`, `mode`, `platform`, `status`, `evidence`, `issues`, and `findings`. Replaying retains the original collection timestamp/platform when recorded. Finding IDs are stable within this initial schema. Issues and bounds are preserved, so unavailable data is not silently presented as a successful check.

## Permissions and operational behavior

Start as a normal user. Some service, event-log, process-path, registry, and filesystem evidence can require additional privileges; failures are reported as collection issues. Elevation may improve coverage but does not guarantee access to every protected resource.

The tool does not terminate processes, change services, modify PATH/hosts/registry/firewall, delete files, install updates, or restart the computer. Network tools make the explicitly requested DNS/TCP/TLS probes. Reports can contain local paths, account names, hosts, process/service names, event messages, and public certificate metadata; review a report before sharing it. There is no telemetry or report-upload feature.

## Test and develop

```powershell
dotnet build WinTlsDoctor.csproj -c Release
dotnet run --project tests/Checks.csproj -c Release
dotnet run --project WinTlsDoctor.csproj -- --input tests/fixture.json --json
```

The dependency-free test executable uses assertions and exits nonzero on failure. Run it with `dotnet run`, not `dotnet test`. Fixtures are synthetic and use reserved example addresses/names. CI builds and runs fixtures on Linux and Windows; Windows also exercises the live collector where applicable and publishes a standalone x64 executable. TLS tests use isolated loopback endpoints, reject an untrusted certificate, and check timeout behavior. Disk tests use temporary directories and check reparse-point skipping where link creation is permitted.

Each repository is independent. `Core.cs` provides strict option parsing, snapshot replay, reporting, cancellation, and a bounded collector launcher. `Tool.cs` owns the diagnostic rules and native collection. Where present, `Collector.ps1` is embedded into the executable, uses built-in Windows inventory commands, and receives validated parameters through environment variables rather than interpolating user input into script code. Its subprocess is capped at 90 seconds and 8 MiB per output stream. Execution policy is not changed or bypassed.

This is a focused initial release. CI smoke tests establish that collectors execute on the hosted Windows runner, not that every Windows policy, locale, domain, or protected application is covered. Findings identify evidence and next checks; configuration changes remain a separate administrative decision.

## License

MIT
