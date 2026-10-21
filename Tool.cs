using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Win32;
namespace WinDiagnostics;
public static class Tool
{
    public const string Name="win-tls-doctor";
    public static readonly string[] ValueOptions=["--url","--timeout","--revocation"];
    public static readonly string[] Flags=[];
    public const string Help="win-tls-doctor --url https://example.com [--timeout 15] [--revocation online|offline|none] [--json]\nTests direct DNS/TCP/TLS and certificate validation. Sends no HTTP request. Reports proxy settings but does not use them or execute PAC files.";
    public static Uri Target(string input)
    {
        if(!Uri.TryCreate(input,UriKind.Absolute,out var uri)||uri.Scheme!="https"||string.IsNullOrEmpty(uri.Host)||uri.UserInfo.Length>0)throw new ArgumentException("--url must be an HTTPS URL without embedded credentials.");
        return uri;
    }
    public static void ValidateOptions(Options o){Target(o.Get("--url"));o.Number("--timeout",15,1,60);if(o.Get("--revocation","online") is not ("online" or "offline" or "none"))throw new ArgumentException("--revocation must be online, offline, or none.");}
    public static async Task<Collection> Collect(Options o,CancellationToken ct)
    {
        var uri=Target(o.Get("--url"));var seconds=o.Number("--timeout",15,1,60);var mode=o.Get("--revocation","online");
        var evidence=new JsonObject{["target"]=uri.GetLeftPart(UriPartial.Authority),["host"]=uri.IdnHost,["port"]=uri.Port,["timeoutSeconds"]=seconds,["connectionMode"]="direct",["revocationMode"]=mode,["dns"]=new JsonObject{["success"]=false},["tcp"]=new JsonObject{["attempted"]=false},["tls"]=new JsonObject{["attempted"]=false},["proxy"]=new JsonObject()};
        var issues=new JsonArray();
        if(OperatingSystem.IsWindows())
        {
            try
            {
                using var key=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                evidence["proxy"]=new JsonObject{["userProxyEnabled"]=Convert.ToInt32(key?.GetValue("ProxyEnable",0)??0)!=0,["userProxyServer"]=RedactProxy(key?.GetValue("ProxyServer")?.ToString()),["pacConfigured"]=!string.IsNullOrWhiteSpace(key?.GetValue("AutoConfigURL")?.ToString()),["httpsProxyEnvironmentSet"]=!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("HTTPS_PROXY")),["httpProxyEnvironmentSet"]=!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("HTTP_PROXY")),["note"]="Current-user Internet Settings only; WinHTTP, application-specific, automatic discovery, and effective policy may differ."};
            }
            catch(Exception ex)when(ex is UnauthorizedAccessException or System.Security.SecurityException or IOException){issues.Add(new JsonObject{["area"]="proxy-inventory",["message"]=ex.Message});}
        }
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(ct);budget.CancelAfter(TimeSpan.FromSeconds(seconds));
        try
        {
            var addresses=await Dns.GetHostAddressesAsync(uri.IdnHost,budget.Token);
            evidence["dns"]=new JsonObject{["success"]=addresses.Length>0,["addresses"]=J.Array(addresses.Select(a=>a.ToString()))};
        }
        catch(Exception ex)when(ex is SocketException or OperationCanceledException){if(ct.IsCancellationRequested)throw new OperationCanceledException(ct);evidence["dns"]=new JsonObject{["success"]=false,["error"]=ex is OperationCanceledException?"Shared DNS/TCP/TLS time budget expired.":ex.Message};return new(evidence,issues);}
        using var client=new TcpClient();
        try
        {
            evidence["tcp"]=new JsonObject{["attempted"]=true,["success"]=false};
            await client.ConnectAsync(uri.IdnHost,uri.Port,budget.Token);
            evidence["tcp"]=new JsonObject{["attempted"]=true,["success"]=true,["remoteEndpoint"]=client.Client.RemoteEndPoint?.ToString()};
        }
        catch(Exception ex)when(ex is SocketException or OperationCanceledException){if(ct.IsCancellationRequested)throw new OperationCanceledException(ct);evidence["tcp"]!["error"]=ex is OperationCanceledException?"Shared DNS/TCP/TLS time budget expired.":ex.Message;return new(evidence,issues);}
        var tls=new JsonObject{["attempted"]=true,["success"]=false,["validationObserved"]=false};evidence["tls"]=tls;
        using var stream=new SslStream(client.GetStream(),false,(_,certificate,chain,errors)=>
        {
            tls["validationObserved"]=true;tls["policyErrors"]=errors.ToString();
            tls["chainStatus"]=new JsonArray((chain?.ChainStatus??[]).Select(s=>(JsonNode?)new JsonObject{["status"]=s.Status.ToString(),["information"]=s.StatusInformation.Trim()}).ToArray());
            if(certificate is not null)
            {
                using var cert=X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                tls["certificate"]=new JsonObject{["subject"]=cert.Subject,["issuer"]=cert.Issuer,["notBeforeUtc"]=cert.NotBefore.ToUniversalTime().ToString("O"),["notAfterUtc"]=cert.NotAfter.ToUniversalTime().ToString("O"),["sha256"]=cert.GetCertHashString(HashAlgorithmName.SHA256),["subjectAlternativeName"]=cert.Extensions["2.5.29.17"]?.Format(false)};
            }
            // Always enforce the platform's policy result; never accept an invalid certificate.
            return errors==SslPolicyErrors.None;
        });
        try
        {
            await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions{TargetHost=uri.IdnHost,EnabledSslProtocols=SslProtocols.None,CertificateRevocationCheckMode=mode switch{"none"=>X509RevocationMode.NoCheck,"offline"=>X509RevocationMode.Offline,_=>X509RevocationMode.Online},ApplicationProtocols=[SslApplicationProtocol.Http2,SslApplicationProtocol.Http11]},budget.Token);
            tls["success"]=true;tls["protocol"]=stream.SslProtocol.ToString();tls["cipherSuite"]=stream.NegotiatedCipherSuite.ToString();tls["alpn"]=stream.NegotiatedApplicationProtocol.ToString();
        }
        catch(Exception ex)when(ex is AuthenticationException or IOException or OperationCanceledException)
        {if(ct.IsCancellationRequested)throw new OperationCanceledException(ct);tls["error"]=ex is OperationCanceledException?"Shared DNS/TCP/TLS time budget expired.":ex.Message;}
        return new(evidence,issues);
    }
    public static string RedactProxy(string? value)
    {
        if(string.IsNullOrEmpty(value))return "";
        // Proxy inventories need endpoints, not passwords or complete PAC URLs.
        return System.Text.RegularExpressions.Regex.Replace(value,@"[^\s;=]*@","[credentials-redacted]@");
    }
    public static void ValidateEvidence(JsonObject e){J.Require(e,"target","dns","tcp","tls","proxy");foreach(var key in new[]{"dns","tcp","tls","proxy"})if(e[key] is not JsonObject)throw new ArgumentException($"Evidence {key} must be an object.");}
    public static List<Finding> Analyze(JsonObject e)
    {
        var r=new List<Finding>();
        if(!J.Bool(e["dns"],"success"))r.Add(new("tls-dns-failed","error","DNS resolution failed",J.Text(e["dns"],"error"),"Use win-dns-doctor for resolver and direct-server evidence."));
        if(J.Bool(e["tcp"],"attempted")&&!J.Bool(e["tcp"],"success"))r.Add(new("tls-tcp-failed","error","Direct TCP connection failed",J.Text(e["tcp"],"error"),"Review the endpoint, routing, listening service, firewall, and whether a proxy is required. This failure alone does not identify which one is responsible."));
        if(J.Bool(e["tls"],"attempted")&&!J.Bool(e["tls"],"success"))r.Add(new("tls-handshake-failed","error","TLS authentication failed",$"{J.Text(e["tls"],"error")} | policy: {J.Text(e["tls"],"policyErrors","not observed")}","Inspect hostname, validity dates, chain status, server protocol support, and network interception. Certificate validation remained enabled."));
        if(J.Bool(e["tls"],"success"))r.Add(new("tls-handshake-ok","info","The direct TLS handshake validated",$"{J.Text(e["tls"],"protocol")} | {J.Text(e["tls"],"cipherSuite")}. No HTTP request or application authentication was attempted.","If the application still fails, compare its proxy, trust store, client-certificate, and HTTP requirements."));
        if(J.Bool(e["proxy"],"userProxyEnabled")||J.Bool(e["proxy"],"pacConfigured")||J.Bool(e["proxy"],"httpsProxyEnvironmentSet")||J.Bool(e["proxy"],"httpProxyEnvironmentSet"))r.Add(new("proxy-context","info","Proxy configuration may affect other clients","This diagnostic uses a direct socket and does not apply proxy/PAC settings. Its result may differ from a browser or proxied application.","Compare the application's effective proxy configuration; this report does not evaluate PAC logic or WinHTTP settings."));
        if(J.Text(e,"revocationMode")=="none")r.Add(new("revocation-not-checked","warning","Revocation checking was explicitly disabled","Chain trust, hostname, and validity checks still apply, but this run cannot establish revocation status.","Repeat with --revocation online when network conditions permit."));return r;
    }
    public static IEnumerable<string> Describe(JsonObject e){yield return $"Target: {J.Text(e,"target")} | direct | revocation {J.Text(e,"revocationMode")}";yield return $"DNS: {J.Text(e["dns"],"success")} {string.Join(", ",J.Strings(e["dns"],"addresses"))} {J.Text(e["dns"],"error")}";yield return $"TCP: {J.Text(e["tcp"],"success","not attempted")} {J.Text(e["tcp"],"remoteEndpoint")} {J.Text(e["tcp"],"error")}";yield return $"TLS: {J.Text(e["tls"],"success","not attempted")} {J.Text(e["tls"],"protocol")} {J.Text(e["tls"],"policyErrors")} {J.Text(e["tls"],"error")}";if(e["tls"]?["certificate"] is JsonObject cert){yield return $"Certificate: {J.Text(cert,"subject")} | issuer {J.Text(cert,"issuer")}";yield return $"Validity (UTC): {J.Text(cert,"notBeforeUtc")} — {J.Text(cert,"notAfterUtc")}";}yield return $"User proxy configured: {J.Text(e["proxy"],"userProxyEnabled","unknown")} | PAC configured: {J.Text(e["proxy"],"pacConfigured","unknown")}";}
    // TLS integration tests use an isolated loopback TLS endpoint instead of public networks.
    public static string[] SmokeArgs=>[];
}
