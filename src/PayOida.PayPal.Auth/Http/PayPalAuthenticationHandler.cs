using Microsoft.Extensions.Options;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Serialization;

namespace PayOida.PayPal.Auth.Http;

public class PayPalAuthenticationHandler(HttpClient authClient, TimeProvider timeProvider, IOptionsMonitor<PayPalAuthenticationOptions> optionsMonitor) : DelegatingHandler
{
    private PayPalTokenResponse? authenticationToken;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        return SendAsyncInternal(request, cancellationToken);
    }

    private async Task<HttpResponseMessage> SendAsyncInternal(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var options = optionsMonitor.CurrentValue;
        var renewalTime = timeProvider.GetUtcNow() + options.TokenExpirationClockSkew;

        if (authenticationToken is null || authenticationToken.IsExpiredBefore(renewalTime))
            authenticationToken = await RenewToken(options, cancellationToken);

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authenticationToken?.AccessToken);

        return await base.SendAsync(request, cancellationToken);
    }

    private async Task<PayPalTokenResponse?> RenewToken(PayPalAuthenticationOptions options, CancellationToken cancellationToken)
    {
        var tokenEndpoint = new Uri("v1/oauth2/token", UriKind.Relative);
        using var content = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "client_credentials" });
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = content
        };

        var basicAuthToken = getBasicAuthToken();
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", basicAuthToken);

        var response = await authClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<PayPalTokenResponse>(cancellationToken: cancellationToken);

        string getBasicAuthToken()
        {
            var authLiteral = $"{options.ClientId}:{options.ClientSecret}";
            var encodedLiteral = Encoding.UTF8.GetBytes(authLiteral);

            return Convert.ToBase64String(encodedLiteral);
        }
    }

    private sealed class PayPalTokenResponse
    {
        [JsonPropertyName("scope")]
        public required string Scope { get; init; }

        [JsonPropertyName("access_token")]
        public required string AccessToken { get; init; }

        [JsonPropertyName("token_type")]
        public required string TokenType { get; init; }

        [JsonPropertyName("app_id")]
        public required string AppId { get; init; }

        [JsonPropertyName("expires_in")]
        public required int ExpiresIn { get; init; }

        [JsonPropertyName("nonce")]
        public required string Nonce { get; init; }

        private readonly DateTimeOffset requestTime;

        [JsonConstructor]
        public PayPalTokenResponse()
        {
            requestTime = DateTimeOffset.UtcNow;
        }

        public bool IsExpiredBefore(DateTimeOffset reference)
        {
            var expireDate = requestTime.Add(TimeSpan.FromSeconds(ExpiresIn));
            return reference.CompareTo(expireDate) > 0;
        }
    }
}
