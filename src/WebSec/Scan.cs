using System.Net;
using Spectre.Console;
using WebSec.Core;
using WebSec.TUI;

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


        var csp = new AnalyzeCSP(response.Headers);

        foreach (var result in csp.Analyze())
        {
            cspGrid.AddRow(result.ToGridRow());
        }        

        AnsiConsole.Write(cspGrid);
    }
}
