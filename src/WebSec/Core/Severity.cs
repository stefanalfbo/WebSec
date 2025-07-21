namespace WebSec.Core;

/// <summary>
/// Represents the severity levels for security issues.
/// </summary>
public enum Severity
{
    Ok,
    Warning,
    Fail
}

public static class SeverityExtensions
{
    public static string ToEmoji(this Severity severity)
    {
        return severity switch
        {
            Severity.Ok => "✅",
            Severity.Warning => "⚠️",
            Severity.Fail => "⛔️",
            _ => throw new ArgumentOutOfRangeException(nameof(severity), severity, null)
        };
    }
}