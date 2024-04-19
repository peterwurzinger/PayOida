using System.Security.Cryptography.X509Certificates;

namespace PayOida.PayPal.Auth.Webhooks;

public interface IWebhookSignatureCertificateStore
{
    Task<X509Certificate2?> GetCertificateByCertUrl(string certUrl, CancellationToken cancellationToken);
}
