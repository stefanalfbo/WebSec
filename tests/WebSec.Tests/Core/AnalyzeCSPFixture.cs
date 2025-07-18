using System.Net.Http.Headers;
using WebSec.Core;

namespace WebSec.Tests.Core;

public class AnalyzeCSPFixture
{
    [Fact]
    public void Directives_should_not_be_empty_when_a_value_exists()
    {
        // Arrange
        var responseMessage = new HttpResponseMessage();
        responseMessage.Headers.Add("Content-Security-Policy", "default-src 'self'");

        // Act
        var analyzeCSP = new AnalyzeCSP(responseMessage.Headers);

        // Assert
        Assert.NotEmpty(analyzeCSP.Directives);
    }

    [Fact]
    public void Directives_should_be_empty_when_no_value_exists()
    {
        // Arrange
        var responseMessage = new HttpResponseMessage();

        // Act
        var analyzeCSP = new AnalyzeCSP(responseMessage.Headers);

        // Assert
        Assert.Empty(analyzeCSP.Directives);
    }

    [Fact]
    public void Directives_should_be_seperated_by_semicolons()
    {
        // Arrange
        var responseMessage = new HttpResponseMessage();
        responseMessage.Headers.Add("Content-Security-Policy", "default-src 'self'; img-src 'self' example.com");

        // Act
        var analyzeCSP = new AnalyzeCSP(responseMessage.Headers);

        // Assert
        Assert.Equal(2, analyzeCSP.Directives.Count());
        Assert.Contains("default-src 'self'", analyzeCSP.Directives);
        Assert.Contains("img-src 'self' example.com", analyzeCSP.Directives);
    }
}