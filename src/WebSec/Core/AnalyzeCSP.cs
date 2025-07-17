using System.Net.Http.Headers;

namespace WebSec.Core;

public class AnalyzeCSP
{
    private readonly IEnumerable<string> _cspHeaders;
    private const string NAME = "CSP Clickjacking Protection";

    public AnalyzeCSP(HttpResponseHeaders headers)
    {
        if (headers.TryGetValues("Content-Security-Policy", out var cspHeaders))
        {
            _cspHeaders = cspHeaders;
        }
        else
        {
            _cspHeaders = Enumerable.Empty<string>();
        }
    }

    public IEnumerable<string> CspHeaders => _cspHeaders;
}