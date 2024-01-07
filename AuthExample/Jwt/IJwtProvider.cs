using System.Security.Claims;

namespace AuthExample;

public interface IJwtProvider
{
    string GenerateToken(List<Claim> authClaims);
    string GenerateRefreshToken();
    ClaimsPrincipal GetPrincipalFromExpiredToken(string token);

    //void SaveRefreshToken(string userId, string refreshToken);
    //string? GetRefreshToken(string userId);
    //void RemoveRefreshToken(string userId);
    //void RemoveRefreshTokenByToken(string refreshToken);
}