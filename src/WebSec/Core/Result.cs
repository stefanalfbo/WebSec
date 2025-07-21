namespace WebSec.Core;

public class Result(Severity severity, string name, string value)
{
    public Severity Severity { get; private set; } = severity;
    public string Name { get; private set; } = name;
    public string Comment { get; private set; } = value;
}