using Spectre.Console;
using WebSec.Core;

namespace WebSec.TUI;

public static class ResultExtensions
{
    public static Text[] ToGridRow(this Result row)
    {
        return [
            new Text(row.Severity.ToEmoji(), new Style(Color.White, Color.Black)).Centered(),
            new Text(row.Name, new Style(Color.White, Color.Black)).LeftJustified(),
            new Text(row.Comment, new Style(Color.White, Color.Black)).LeftJustified()
        ];
    }
}