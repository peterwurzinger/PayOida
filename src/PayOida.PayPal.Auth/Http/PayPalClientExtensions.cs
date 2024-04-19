using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace PayOida.PayPal.Auth.Http;

public static class PayPalClientExtensions
{
    public static IHttpClientBuilder AddPayPalHttpClient<TClient, TImplementation>(this IServiceCollection services)
        where TClient : class
        where TImplementation : class, TClient
    {
        AddCoreServices(services);

        return services.AddHttpClient<TClient, TImplementation>(ConfigurePayPalHttpClient)
                       .AddHttpMessageHandler<PayPalAuthenticationHandler>();
    }

    public static IHttpClientBuilder AddPayPalHttpClient<TClient>(this IServiceCollection services)
        where TClient : class
    {
        AddCoreServices(services);

        return services.AddHttpClient<TClient>(ConfigurePayPalHttpClient)
                       .AddHttpMessageHandler<PayPalAuthenticationHandler>();
    }

    public static IHttpClientBuilder AddPayPalAuthentication(this IHttpClientBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        AddCoreServices(builder.Services);

        return builder.AddHttpMessageHandler<PayPalAuthenticationHandler>();
    }

    private static void AddCoreServices(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<PayPalAuthenticationOptions>()
                .ValidateOnStart();
        services.TryAddSingleton<IValidateOptions<PayPalAuthenticationOptions>, PayPalAuthenticationOptionsValidation>();
        services.AddHttpClient<PayPalAuthenticationHandler>(ConfigurePayPalHttpClient);
    }

    private static void ConfigurePayPalHttpClient(IServiceProvider serviceProvider, HttpClient httpClient)
    {
        var payPalOptions = serviceProvider.GetRequiredService<IOptions<PayPalAuthenticationOptions>>();
        httpClient.BaseAddress = payPalOptions.Value.Endpoint;
    }
}
