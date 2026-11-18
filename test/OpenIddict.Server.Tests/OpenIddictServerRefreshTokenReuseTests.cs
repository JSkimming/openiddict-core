using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerRefreshTokenReuseTests
{
    [Theory]
    [InlineData(TokenTypeIdentifiers.RefreshToken, "grant", true,  true,  true)]
    [InlineData(TokenTypeIdentifiers.RefreshToken, "grant", false, true,  false)]
    [InlineData(TokenTypeIdentifiers.RefreshToken, null,    true,  true,  false)]
    [InlineData(TokenTypeIdentifiers.RefreshToken, "grant", true, false, false, true)]
    [InlineData(TokenTypeIdentifiers.Private.AuthorizationCode, "grant", true, false, false)]
    public async Task ValidateTokenEntry_AppliesRefreshTokenReusePolicy(
        string type, string? identifier, bool enabled, bool notify, bool revoke, bool withinLeeway = false)
    {
        // Arrange
        var token = new object();
        var authorization = new object();
        var tokens = new Mock<IOpenIddictTokenManager>();
        tokens.Setup(manager => manager.FindByIdAsync("token", default)).ReturnsAsync(token);
        tokens.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, default)).ReturnsAsync(true);
        tokens.Setup(manager => manager.GetRedemptionDateAsync(token, default)).ReturnsAsync(DateTimeOffset.UtcNow);
        var authorizations = new Mock<IOpenIddictAuthorizationManager>();
        authorizations.Setup(manager => manager.FindByIdAsync("grant", default)).ReturnsAsync(authorization);
        authorizations.Setup(manager => manager.TryRevokeAsync(authorization, default)).ReturnsAsync(true);

        using var provider = new ServiceCollection()
            .AddSingleton(tokens.Object)
            .AddSingleton(authorizations.Object)
            .AddSingleton<IOpenIddictServerDispatcher, OpenIddictServerDispatcher>()
            .AddSingleton<ILogger<OpenIddictServerDispatcher>>(NullLogger<OpenIddictServerDispatcher>.Instance)
            .BuildServiceProvider();

        var options = new OpenIddictServerOptions
        {
            EnableAuthorizationRevocationOnRefreshTokenReuse = enabled,
            TimeProvider = TimeProvider.System,
            RefreshTokenReuseLeeway = withinLeeway ? TimeSpan.FromDays(1) : null
        };

        var notifications = new List<RefreshTokenReuseDetectedContext>();
        options.Handlers.Add(OpenIddictServerHandlerDescriptor.CreateBuilder<RefreshTokenReuseDetectedContext>()
            .UseInlineHandler(context =>
            {
                notifications.Add(context);
                return ValueTask.CompletedTask;
            })
            .Build());

        var context = new ValidateTokenContext(new OpenIddictServerTransaction
        {
            CancellationToken = default,
            Options = options,
            ServiceProvider = provider
        })
        {
            TokenId = "token",
            AuthorizationId = identifier,
            Principal = new ClaimsPrincipal(new ClaimsIdentity()).SetTokenType(type)
        };

        // Act
        await new OpenIddictServerHandlers.Protection.ValidateTokenEntry().HandleAsync(context);

        // Assert
        Assert.Equal(!withinLeeway, context.IsRejected);
        Assert.Equal(withinLeeway ? null : Errors.InvalidToken, context.Error);
        if (notify)
        {
            var notification = Assert.Single(notifications);
            Assert.Equal("token", notification.TokenId);
            Assert.Equal(identifier, notification.AuthorizationId);
        }
        else
        {
            Assert.Empty(notifications);
        }

        tokens.Verify(manager => manager.RevokeByAuthorizationIdAsync("grant", default),
            identifier is null || withinLeeway ? Times.Never() : Times.Once());
        authorizations.Verify(manager => manager.TryRevokeAsync(authorization, default), revoke ? Times.Once() : Times.Never());
    }

    [Fact]
    public async Task ValidateTokenEntry_NotifiesHostWhenRevokingTheTokenChainFails()
    {
        // Arrange
        var token = new object();
        var tokens = new Mock<IOpenIddictTokenManager>();
        tokens.Setup(manager => manager.FindByIdAsync("token", default)).ReturnsAsync(token);
        tokens.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, default)).ReturnsAsync(true);
        tokens.Setup(manager => manager.RevokeByAuthorizationIdAsync("grant", default))
            .ThrowsAsync(new InvalidOperationException());

        var dispatcher = new Mock<IOpenIddictServerDispatcher>();
        using var provider = new ServiceCollection()
            .AddSingleton(tokens.Object)
            .AddSingleton(dispatcher.Object)
            .AddSingleton<ILogger<OpenIddictServerDispatcher>>(NullLogger<OpenIddictServerDispatcher>.Instance)
            .BuildServiceProvider();

        var context = new ValidateTokenContext(new OpenIddictServerTransaction
        {
            CancellationToken = default,
            Options = new OpenIddictServerOptions
            {
                DisableAuthorizationStorage = true,
                EnableAuthorizationRevocationOnRefreshTokenReuse = true,
                RefreshTokenReuseLeeway = null
            },
            ServiceProvider = provider
        })
        {
            TokenId = "token",
            AuthorizationId = "grant",
            Principal = new ClaimsPrincipal(new ClaimsIdentity()).SetTokenType(TokenTypeIdentifiers.RefreshToken)
        };

        // Act
        await new OpenIddictServerHandlers.Protection.ValidateTokenEntry().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        dispatcher.Verify(dispatcher => dispatcher.DispatchAsync(It.Is<RefreshTokenReuseDetectedContext>(
            notification => notification.TokenId == "token" && notification.AuthorizationId == "grant")), Times.Once());
    }
}
