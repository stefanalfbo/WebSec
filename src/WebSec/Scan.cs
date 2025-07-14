using System.Net;
using System.Net.Http;

namespace WebSec;

public class Scan
{
    public async Task ScanSiteAsync(string url)
    {
        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer
        };

        using var client = new HttpClient(handler);
        var response = await client.GetAsync(url);

        Console.WriteLine($"Response {response}");

        Uri uri = new Uri(url);
        CookieCollection cookies = cookieContainer.GetCookies(uri);

        foreach (Cookie cookie in cookies)
        {
            Console.WriteLine($"{cookie.Name} = {cookie.Value}");
        }

        CheckCSPHeader(response);
    }

    public void CheckCSPHeader(HttpResponseMessage response)
    {
        if (response.Headers.TryGetValues("Content-Security-Policy", out var cspHeaders))
        {
            foreach (var csp in cspHeaders)
            {
                Console.WriteLine($"CSP: {csp}");
                

                if (csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase))
                {
                    var frameAncestorsIndex = csp.IndexOf("frame-ancestors", StringComparison.OrdinalIgnoreCase);
                    var semicolonIndex = csp.IndexOf(';', frameAncestorsIndex);
                    string frameAncestorsPart = semicolonIndex == -1
                        ? csp.Substring(frameAncestorsIndex)
                        : csp.Substring(frameAncestorsIndex, semicolonIndex - frameAncestorsIndex);

                    if (frameAncestorsPart.Contains("'none'"))
                    {
                        Console.WriteLine("✅ CSP prevents clickjacking. Frame ancestors are blocked.");
                    } else if (frameAncestorsPart.Contains("'self'"))
                    {
                        Console.WriteLine("⚠️ CSP allows same-origin framing. Clickjacking risk may exist.");
                    }
                    else if (frameAncestorsPart.Contains("*"))
                    {
                        Console.WriteLine("⚠️ CSP allows framing from any origin. High clickjacking risk.");
                    }
                    else
                    {
                        Console.WriteLine("⚠️ CSP does not prevent clickjacking. Frame ancestors are allowed.");
                    }
                }
            }
        }
        else
        {
            Console.WriteLine("No CSP header found.");
        }
    }
}