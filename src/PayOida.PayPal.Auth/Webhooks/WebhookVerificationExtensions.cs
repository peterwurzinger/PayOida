using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PayOida.PayPal.Auth.Http;
using PayOida.PayPal.Auth.Webhooks.Authorization;

namespace PayOida.PayPal.Auth.Webhooks;

public static class WebhookVerificationExtensions
{
    public static IServiceCollection AddPayPalWebhookVerification(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IWebhookSignatureCertificateStore, CachedWebhookSignatureCertificateStore>();
        services.TryAddSingleton<PayPalWebhookVerifier>();
        
        services.AddScoped<IAuthorizationHandler, PayPalWebhookVerficationHandler>();

        services.AddOptionsWithValidateOnStart<PayPalWebhookVerificationOptions, PayPalWebhookVerificationOptionsValidation>();

        services.AddDistributedMemoryCache();
        services.AddHttpContextAccessor();
        services.AddAuthorizationCore();

        return services;
    }

    public static AuthorizationPolicyBuilder VerifyPayPalWebhook(this AuthorizationPolicyBuilder builder, string webhookId)
    {
        ArgumentException.ThrowIfNullOrEmpty(webhookId);

        builder.AddRequirements(new PayPalWebhookVerficationRequirement(webhookId));

        return builder;
    }
}
