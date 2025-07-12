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
    }
}