using Spectre.Console.Cli;

namespace WebSec.Setting;

public class ScanSettings : CommandSettings
{
    [CommandArgument(0, "[url]")]
    public required string Url { get; set; }
}