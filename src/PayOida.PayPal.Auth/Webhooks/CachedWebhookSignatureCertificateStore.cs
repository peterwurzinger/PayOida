using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using System.Security.Cryptography.X509Certificates;

namespace PayOida.PayPal.Auth.Webhooks;

public sealed class CachedWebhookSignatureCertificateStore(HttpClient httpClient, IDistributedCache distributedCache, IOptionsMonitor<PayPalWebhookVerificationOptions> optionsMonitor) : IWebhookSignatureCertificateStore
{
    public async Task<X509Certificate2?> GetCertificateByCertUrl(string certUrl, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certUrl);

        var uri = new Uri(certUrl);
        var options = optionsMonitor.CurrentValue;

        if (!ValidateCertUrl(uri, options))
            return null;

        var cannonicalCacheKey = uri.ToString();

        var certData = await distributedCache.GetAsync(cannonicalCacheKey, cancellationToken);
        var cacheHit = certData is not null;

        certData ??= await httpClient.GetByteArrayAsync(uri, cancellationToken);

        var cert = new X509Certificate2(certData);
        if (!options.ValidateCertificate(cert))
        {
            if (cacheHit)
                await distributedCache.RemoveAsync(cannonicalCacheKey, cancellationToken);

            cert.Dispose();
            return null;
        }

        if (!cacheHit)
            await StoreInCache(cannonicalCacheKey, cert, cancellationToken);

        return cert;
    }

    private static bool ValidateCertUrl(Uri uri, PayPalWebhookVerificationOptions options)
    {
        var isHttps = string.Equals("https", uri.Scheme, StringComparison.OrdinalIgnoreCase);

        if (options.CertificateDownloadHostWhitelist.Count == 0)
            return isHttps;
        
        var downloadUrlWhitelisted = options.CertificateDownloadHostWhitelist.Contains(uri.Host, StringComparer.OrdinalIgnoreCase);

        return isHttps && downloadUrlWhitelisted;
    }

    private Task StoreInCache(string cacheKey, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        var entryOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = certificate.NotAfter
        };
        return distributedCache.SetAsync(cacheKey, certificate.RawData, entryOptions, cancellationToken);
    }
}
