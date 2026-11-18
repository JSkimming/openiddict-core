using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerRevocationTests
{
    [Theory]
    [InlineData(true, TokenTypeIdentifiers.RefreshToken, "grant", true)]
    [InlineData(false, TokenTypeIdentifiers.RefreshToken, "grant", false)]
    [InlineData(true, TokenTypeIdentifiers.AccessToken, "grant", false)]
    [InlineData(true, TokenTypeIdentifiers.RefreshToken, null, false)]
    public async Task RevokeToken_RevokesRelatedEntriesWhenConfigured(
        bool enabled, string type, string? authorizationId, bool cascade)
    {
        // Arrange
        var token = new object();
        var manager = new Mock<IOpenIddictTokenManager>();
        manager.Setup(manager => manager.FindByIdAsync("token", default)).ReturnsAsync(token);
        manager.Setup(manager => manager.GetAuthorizationIdAsync(token, default)).ReturnsAsync(authorizationId);
        manager.Setup(manager => manager.TryRevokeAsync(token, default)).ReturnsAsync(true);
        manager.Setup(manager => manager.RevokeByAuthorizationIdAsync("grant", default)).ReturnsAsync(2L);

        using var provider = new ServiceCollection().AddSingleton(manager.Object).BuildServiceProvider();
        var context = new OpenIddictServerEvents.HandleRevocationRequestContext(new OpenIddictServerTransaction
        {
            CancellationToken = default,
            Options = new OpenIddictServerOptions { EnableRefreshTokenRevocationCascade = enabled },
            ServiceProvider = provider
        })
        {
            GenericTokenPrincipal = new ClaimsPrincipal(new ClaimsIdentity()).SetTokenId("token").SetTokenType(type)
        };

        // Act
        await new OpenIddictServerHandlers.Revocation.RevokeToken().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        manager.Verify(manager => manager.RevokeByAuthorizationIdAsync("grant", default), cascade ? Times.Once() : Times.Never());
        manager.Verify(manager => manager.TryRevokeAsync(token, default), cascade ? Times.Never() : Times.Once());
    }
}
