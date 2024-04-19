using Microsoft.Extensions.Options;

namespace PayOida.PayPal.Auth.Http;

public class PayPalAuthenticationOptions
{
    public required Uri Endpoint { get; init; }
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public TimeSpan TokenExpirationClockSkew { get; init; } = TimeSpan.FromMinutes(5);
}

public sealed class PayPalAuthenticationOptionsValidation : IValidateOptions<PayPalAuthenticationOptions>
{
    public ValidateOptionsResult Validate(string? name, PayPalAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var resultBuilder = new ValidateOptionsResultBuilder();

        if (options.Endpoint is null)
            resultBuilder.AddError($"{nameof(PayPalAuthenticationOptions.Endpoint)} must not be null.", nameof(PayPalAuthenticationOptions.Endpoint));

        if (options.ClientId is null)
            resultBuilder.AddError($"{nameof(PayPalAuthenticationOptions.ClientId)} must not be null.", nameof(PayPalAuthenticationOptions.ClientId));

        if (options.ClientSecret is null)
            resultBuilder.AddError($"{nameof(PayPalAuthenticationOptions.ClientSecret)} must not be null.", nameof(PayPalAuthenticationOptions.ClientSecret));

        return resultBuilder.Build();
    }
}
