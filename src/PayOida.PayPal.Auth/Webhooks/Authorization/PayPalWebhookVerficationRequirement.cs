using Microsoft.AspNetCore.Authorization;

namespace PayOida.PayPal.Auth.Webhooks.Authorization;

public sealed class PayPalWebhookVerficationRequirement : IAuthorizationRequirement
{
    public string WebhookId { get; }
    public PayPalWebhookVerficationRequirement(string webhookId)
    {
        ArgumentException.ThrowIfNullOrEmpty(webhookId);

        WebhookId = webhookId;
    }
}
