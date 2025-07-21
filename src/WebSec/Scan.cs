using System.Net;
using Spectre.Console;
using WebSec.Core;

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

        if (cookies.Count == 0)
        {
            Console.WriteLine("No cookies found.");
            return;
        }
        else
        {
            Console.WriteLine($"Found {cookies.Count} cookies:");
            foreach (Cookie cookie in cookies)
            {
                Console.WriteLine($"{cookie.Name} = {cookie.Value}");
            }
        }


        CheckCSPHeader(response);
    }

    public void CheckCSPHeader(HttpResponseMessage response)
    {
        var cspGrid = new Grid();
        cspGrid.AddColumn();
        cspGrid.AddColumn();
        cspGrid.AddColumn();
        cspGrid.AddRow([
            new Text("Severity", new Style(Color.Green, Color.Black)).Centered(),
            new Text("Name", new Style(Color.Green, Color.Black)).LeftJustified(),
            new Text("Comment", new Style(Color.Green, Color.Black)).LeftJustified()
        ]);

        if (response.Headers.TryGetValues("Content-Security-Policy", out var cspHeaders))
        {
            foreach (var csp in cspHeaders)
            {
                Console.WriteLine($"CSP: {csp}");


                if (csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase))
                {
                    cspGrid.AddRow(AnalyzeCspFrameAncestors(csp).ToGridRow());
                }
            }
        }
        else
        {
            Console.WriteLine("No CSP header found.");
        }

        AnsiConsole.Write(cspGrid);
    }

    private static AnalyzeRuleRow AnalyzeCspFrameAncestors(string csp)
    {
        const string NAME = "Clickjacking protection, using frame-ancestors";
        var frameAncestorsIndex = csp.IndexOf("frame-ancestors", StringComparison.OrdinalIgnoreCase);
        var semicolonIndex = csp.IndexOf(';', frameAncestorsIndex);
        string frameAncestorsPart = semicolonIndex == -1
            ? csp.Substring(frameAncestorsIndex)
            : csp.Substring(frameAncestorsIndex, semicolonIndex - frameAncestorsIndex);

        if (frameAncestorsPart.Contains("'none'"))
        {
            return new AnalyzeRuleRow
            (
                Severity.Ok,
                NAME,
                "CSP prevents clickjacking by blocking all frame ancestors."
            );
        }
        else if (frameAncestorsPart.Contains("'self'"))
        {
            return new AnalyzeRuleRow
            (
                Severity.Warning,
                NAME,
                "CSP allows same-origin framing. Clickjacking risk may exist."
            );
        }
        else if (frameAncestorsPart.Contains("*"))
        {
            return new AnalyzeRuleRow
            (
                Severity.Fail,
                NAME,
                "CSP allows framing from any origin. High clickjacking risk."
            );
        }
        else
        {
            return new AnalyzeRuleRow
            (
                Severity.Fail,
                NAME,
                "CSP does not prevent clickjacking. Frame ancestors are allowed."
            );
        }
    }
}

public class AnalyzeRuleRow {
    public Severity Severity { get; set; }
    public string Name { get; set; }
    public string Comment { get; set; }
    

    public AnalyzeRuleRow(Severity severity, string name, string value)
    {
        Severity = severity;
        Name = name;
        Comment = value;
    }
}

public static class AnalyzeRuleRowExtensions
{
    public static Text[] ToGridRow(this AnalyzeRuleRow row)
    {
        return [
            new Text(row.Severity.ToEmoji(), new Style(Color.White, Color.Black)).Centered(),
            new Text(row.Name, new Style(Color.White, Color.Black)).LeftJustified(),
            new Text(row.Comment, new Style(Color.White, Color.Black)).LeftJustified()
        ];
    }
}
