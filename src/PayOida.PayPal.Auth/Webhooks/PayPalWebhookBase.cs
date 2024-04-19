using System.Text.Json.Serialization;

namespace PayOida.PayPal.Auth.Webhooks;

public record PayPalWebhookBase
{
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    [JsonPropertyName("create_time")]
    public required string CreateTime { get; init; }

    [JsonPropertyName("resource_type")]
    public required string ResourceType { get; init; }

    [JsonPropertyName("event_type")]
    public required string EventType { get; init; }

    [JsonPropertyName("summary")]
    public required string Summary { get; init; }

    [JsonPropertyName("event_version")]
    public required string EventVersion { get; init; }
}

public record PayPalWebhookBase<TData> : PayPalWebhookBase
{
    [JsonPropertyName("resource")]
    public required TData Resource { get; init; }
}
