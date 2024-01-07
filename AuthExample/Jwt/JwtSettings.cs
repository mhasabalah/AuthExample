namespace AuthExample;

public class JwtOptions
{
    public string Secret { get; set; } = null!;
    public TimeSpan TokenLifetime { get; set; }
}
