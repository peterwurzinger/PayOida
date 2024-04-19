using Microsoft.Extensions.Caching.Distributed;
using System.Security.Cryptography.X509Certificates;

namespace PayOida.PayPal.Auth.Webhooks;

public sealed class CachedWebhookSignatureCertificateStore(HttpClient httpClient, IDistributedCache distributedCache) : IWebhookSignatureCertificateStore
{
    public async Task<X509Certificate2?> GetCertificateByCertUrl(string certUrl, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certUrl);

        var uri = new Uri(certUrl);
        var cannonicalCacheKey = uri.ToString();

        var certData = await distributedCache.GetAsync(cannonicalCacheKey, cancellationToken);
        var cacheHit = certData is not null;

        certData ??= await httpClient.GetByteArrayAsync(uri, cancellationToken);

        var cert = new X509Certificate2(certData);
        if (!cert.Verify())
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

    private Task StoreInCache(string cacheKey, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        var entryOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = certificate.NotAfter
        };
        return distributedCache.SetAsync(cacheKey, certificate.RawData, entryOptions, cancellationToken);
    }
}
