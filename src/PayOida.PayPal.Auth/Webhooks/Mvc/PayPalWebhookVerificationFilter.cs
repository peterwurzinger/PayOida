using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace PayOida.PayPal.Auth.Webhooks.Mvc;

public sealed class PayPalWebhookVerificationFilter(PayPalWebhookVerifier verifier, string webhookId) : IAsyncAuthorizationFilter
{
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var webhookVerificationSuccessful = await verifier.Verify(webhookId, context.HttpContext.Request, context.HttpContext.RequestAborted);
        if (!webhookVerificationSuccessful)
            context.Result = new BadRequestResult();
    }
}
