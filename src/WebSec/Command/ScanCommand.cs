using Spectre.Console.Cli;
using WebSec.Setting;

namespace WebSec.Command;

public class ScanCommand : Command<ScanSettings>
{
    public override int Execute(CommandContext context, ScanSettings settings)
    {
        if (string.IsNullOrEmpty(settings.Url))
        {
            Console.WriteLine("Please provide a URL to scan.");
            return 1;
        }

        var scanner = new Scan();
        scanner.ScanSiteAsync(settings.Url).GetAwaiter().GetResult();

        return 0;
    }
}