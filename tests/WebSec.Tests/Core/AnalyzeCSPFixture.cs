using System.Net.Http.Headers;
using WebSec.Core;

namespace WebSec.Tests.Core;

public class AnalyzeCSPFixture
{
    [Fact]
    public void CspHeaders_Should_not_be_empty_when_a_value_exists()
    {
        // Arrange
        var responseMessage = new HttpResponseMessage();
        responseMessage.Headers.Add("Content-Security-Policy", "default-src 'self'");

        // Act
        var analyzeCSP = new AnalyzeCSP(responseMessage.Headers);

        // Assert
        Assert.NotEmpty(analyzeCSP.CspHeaders);
    }

    [Fact]
    public void CspHeaders_Should_be_empty_when_no_value_exists()
    {
        // Arrange
        var responseMessage = new HttpResponseMessage();

        // Act
        var analyzeCSP = new AnalyzeCSP(responseMessage.Headers);

        // Assert
        Assert.Empty(analyzeCSP.CspHeaders);
    }
}