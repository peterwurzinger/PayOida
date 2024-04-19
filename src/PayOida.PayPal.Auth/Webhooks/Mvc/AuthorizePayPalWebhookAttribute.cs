using Microsoft.AspNetCore.Mvc;

namespace PayOida.PayPal.Auth.Webhooks.Mvc;

public sealed class AuthorizePayPalWebhookAttribute : TypeFilterAttribute
{
    public AuthorizePayPalWebhookAttribute(string webhookId) : base(typeof(PayPalWebhookVerificationFilter))
    {
        ArgumentException.ThrowIfNullOrEmpty(webhookId);

        Arguments = [webhookId];
        WebhookId = webhookId;
    }

    public string WebhookId { get; }
}
