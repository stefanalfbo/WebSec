using Spectre.Console.Cli;
using WebSec.Command;

namespace WebSec;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var app = new CommandApp();

        app.Configure(config =>
        {
            config.AddCommand<ScanCommand>("scan");
        });
        
        return await app.RunAsync(args);
    }
}

