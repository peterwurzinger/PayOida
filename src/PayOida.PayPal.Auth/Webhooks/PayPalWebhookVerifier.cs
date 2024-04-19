using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PayOida.PayPal.Auth.Webhooks;

public sealed class PayPalWebhookVerifier(IWebhookSignatureCertificateStore payPalSignatureCertificateCache)
{
    public async Task<bool> Verify(string webhookId, string authAlgo, string certUrl, string transmissionId, string transmissionSig, string transmissionTime, Stream stream, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(webhookId);
        ArgumentException.ThrowIfNullOrEmpty(authAlgo);
        ArgumentException.ThrowIfNullOrEmpty(certUrl);
        ArgumentException.ThrowIfNullOrEmpty(transmissionId);
        ArgumentException.ThrowIfNullOrEmpty(transmissionSig);
        ArgumentException.ThrowIfNullOrEmpty(transmissionTime);
        ArgumentNullException.ThrowIfNull(stream);

        if (!authAlgo.EndsWith("withRSA", StringComparison.OrdinalIgnoreCase))
            throw new NotImplementedException("Only RSA is supported as signature algorithm.");

        var crc32 = await GetCrc32(stream, cancellationToken);
        var data = $"{transmissionId}|{transmissionTime}|{webhookId}|{crc32}";

        var messageSignature = WebEncoders.Base64UrlDecode(transmissionSig);

        return await VerifySignature(data, messageSignature, certUrl, authAlgo, cancellationToken);
    }

    private static async Task<uint> GetCrc32(Stream stream, CancellationToken cancellationToken)
    {
        var crc32 = new Crc32();
        try
        {
            await crc32.AppendAsync(stream, cancellationToken);
            return crc32.GetCurrentHashAsUInt32();
        }
        finally
        {
            if (stream.CanSeek)
                stream.Seek(0, SeekOrigin.Begin);
        }
    }

    private async Task<bool> VerifySignature(string data, byte[] messageSignature, string certUrl, string authAlgo, CancellationToken cancellationToken)
    {
        using var certificate = await payPalSignatureCertificateCache.GetCertificateByCertUrl(certUrl, cancellationToken);

        if (certificate is null)
            return false;

        using var rsa = certificate.GetRSAPublicKey()
                          ?? throw new InvalidOperationException($"Certificate from URL '{certUrl}' does not contain a public key.");

        var dataBytes = Encoding.UTF8.GetBytes(data);
        var hashAlgorithmName = GetHashAlgorithmName(authAlgo);

        return rsa.VerifyData(dataBytes, messageSignature, hashAlgorithmName, RSASignaturePadding.Pkcs1);
    }

    private static HashAlgorithmName GetHashAlgorithmName(string authAlgorithm)
    {
        //PayPal sends "SHA256withRSA"
        var hashAlgorithmName = authAlgorithm.Replace("withRSA", string.Empty, StringComparison.OrdinalIgnoreCase);
        return new HashAlgorithmName(hashAlgorithmName);
    }
}

public static class PayPalWebhookVerifierExtensions
{
    public static Task<bool> Verify(this PayPalWebhookVerifier verifier, string webhookId, HttpRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var authAlgo = GetSingleHeaderValue(request, "PAYPAL-AUTH-ALGO");
        var certUrl = GetSingleHeaderValue(request, "PAYPAL-CERT-URL");

        var transmissionId = GetSingleHeaderValue(request, "PAYPAL-TRANSMISSION-ID");
        var transmissionSig = GetSingleHeaderValue(request, "PAYPAL-TRANSMISSION-SIG");
        var transmissionTime = GetSingleHeaderValue(request, "PAYPAL-TRANSMISSION-TIME");

        request.EnableBuffering();
        return verifier.Verify(webhookId, authAlgo, certUrl, transmissionId, transmissionSig, transmissionTime, request.Body, cancellationToken);
    }

    private static string GetSingleHeaderValue(HttpRequest request, string headerName)
    {
        var headerValues = request.Headers[headerName];
        if (headerValues.Count == 0)
            throw new ArgumentException($"HTTP header {headerName} was not present.");

        if (headerValues.Count > 1)
            throw new ArgumentException($"Multiple HTTP headers for {headerName} were present.");

        return headerValues.ToString();
    }
}
