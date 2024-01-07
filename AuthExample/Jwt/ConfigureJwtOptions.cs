using Microsoft.Extensions.Options;

namespace AuthExample.Jwt;

public class ConfigureJwtOptions : IConfigureOptions<JwtOptions>
{
    private readonly IConfiguration _configuration;
    public ConfigureJwtOptions(IConfiguration configuration) => _configuration = configuration;

    public void Configure(JwtOptions options) => _configuration.GetSection(nameof(JwtOptions)).Bind(options);
}
