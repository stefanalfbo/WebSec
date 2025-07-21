using System.Net.Http.Headers;

namespace WebSec.Core;

public class AnalyzeCSP : IAnalyze
{    
    public IEnumerable<string> Directives { get; private set; }
    
    public AnalyzeCSP(HttpResponseHeaders headers)
    {
        if (headers.TryGetValues("Content-Security-Policy", out var cspDirectives))
        {
            Directives = cspDirectives
                .SelectMany(directive => directive.Split(';', StringSplitOptions.RemoveEmptyEntries))
                .Select(directive => directive.Trim())
                .Where(directive => !string.IsNullOrWhiteSpace(directive));
        }
        else
        {
            Directives = Enumerable.Empty<string>();
        }
    }

    public IEnumerable<Result> Analyze()
    {
        var results = new List<Result>();
        foreach (var directive in Directives)
        {
            var result = FrameAncestorsCheck(directive);
            if (result != null)
            {
                results.Add(result);
            }
    
        }

        return results;
        
    }

    private Result? FrameAncestorsCheck(string directive)
    {
        const string NAME = "Clickjacking protection, using frame-ancestors";

        if (!string.IsNullOrWhiteSpace(directive))
        {
            if (!directive.StartsWith("frame-ancestors", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
            else if (directive.Contains("'none'"))
            {
                return new Result
                (
                    Severity.Ok,
                    NAME,
                    "CSP prevents clickjacking by blocking all frame ancestors."
                );
            }
            else if (directive.Contains("'self'"))
            {
                return new Result
                (
                    Severity.Warning,
                    NAME,
                    "CSP allows same-origin framing. Clickjacking risk may exist."
                );
            }
            else if (directive.Contains('*'))
            {
                return new Result
                (
                    Severity.Fail,
                    NAME,
                    "CSP allows framing from any origin. High clickjacking risk."
                );
            }
            else
            {
                return new Result
                (
                    Severity.Fail,
                    NAME,
                    "CSP does not prevent clickjacking. Frame ancestors are allowed."
                );
            }
        }

        return null;
    }
}