namespace WebSec.Core;

interface IAnalyze
{
    IEnumerable<Result> Analyze();
}