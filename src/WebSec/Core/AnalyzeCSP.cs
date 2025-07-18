using System.Net.Http.Headers;

namespace WebSec.Core;

public class AnalyzeCSP
{
    private readonly IEnumerable<string> _cspDirectives;
    private const string NAME = "CSP Clickjacking Protection";

    public AnalyzeCSP(HttpResponseHeaders headers)
    {
        if (headers.TryGetValues("Content-Security-Policy", out var cspDirectives))
        {
            _cspDirectives = cspDirectives
                .SelectMany(directive => directive.Split(';', StringSplitOptions.RemoveEmptyEntries))
                .Select(directive => directive.Trim())
                .Where(directive => !string.IsNullOrWhiteSpace(directive));
        }
        else
        {
            _cspDirectives = Enumerable.Empty<string>();
        }
    }

    public IEnumerable<string> Directives => _cspDirectives;
}