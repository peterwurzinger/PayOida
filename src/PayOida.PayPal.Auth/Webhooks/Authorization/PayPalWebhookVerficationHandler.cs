using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace PayOida.PayPal.Auth.Webhooks.Authorization;

public sealed class PayPalWebhookVerficationHandler(IHttpContextAccessor httpContextAccessor, PayPalWebhookVerifier payPalWebhookVerifier) : AuthorizationHandler<PayPalWebhookVerficationRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PayPalWebhookVerficationRequirement requirement)
    {
        var httpContext = httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            context.Fail();
            return;
        }

        var webhookVerificationSuccessful = await payPalWebhookVerifier.Verify(requirement.WebhookId, httpContext.Request, httpContext.RequestAborted);
        if (webhookVerificationSuccessful)
            context.Succeed(requirement);
        else
            context.Fail();
    }
}
