using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace PayOida.PayPal.Auth.Webhooks;

public class PayPalWebhookVerificationOptions
{
    public IReadOnlyCollection<string> CertificateDownloadHostWhitelist { get; init; } = ["certs.paypal.com"];

    public Func<X509Certificate2, bool> ValidateCertificate { get; init; } = cert => cert.Verify();
}

public sealed class PayPalWebhookVerificationOptionsValidation(ILogger<PayPalWebhookVerificationOptionsValidation> logger) : IValidateOptions<PayPalWebhookVerificationOptions>
{
    public ValidateOptionsResult Validate(string? name, PayPalWebhookVerificationOptions options)
    {
        var builder = new ValidateOptionsResultBuilder();

        if (options.CertificateDownloadHostWhitelist is null)
            builder.AddError($"{nameof(PayPalWebhookVerificationOptions.CertificateDownloadHostWhitelist)} must not be null.");
        else if (options.CertificateDownloadHostWhitelist.Count == 0)
            logger.LogWarning($"{nameof(PayPalWebhookVerificationOptions.CertificateDownloadHostWhitelist)} is empty, therefore allowing calls to arbitrary URLs.");

        if (options.ValidateCertificate is null)
            builder.AddError($"{nameof(PayPalWebhookVerificationOptions.ValidateCertificate)} must not be null.");

        return builder.Build();
    }
}
