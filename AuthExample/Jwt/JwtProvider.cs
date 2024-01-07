using AuthExample.Controllers;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthExample;

public sealed class JwtProvider : IJwtProvider
{
    private readonly JwtOptions _options;
    public JwtProvider(IOptions<JwtOptions> options, ApplicationDbContext context, UserManager<ApplicationUser> userManager)
    {
        _options = options.Value;
        _context = context;
        _userManager = userManager;
    }

    public string GenerateToken(List<Claim> authClaims)
    {
        JwtSecurityTokenHandler? tokenHandler = new JwtSecurityTokenHandler();
        byte[]? key = Encoding.ASCII.GetBytes(_options.Secret);

        SecurityTokenDescriptor? tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(authClaims),
            Expires = DateTime.UtcNow.Add(_options.TokenLifetime),
            NotBefore = DateTime.UtcNow.AddMinutes(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        SecurityToken? token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false, //you might want to validate the audience and issuer depending on your use case
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.Secret)),
            ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        SecurityToken securityToken;
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
        var jwtSecurityToken = securityToken as JwtSecurityToken;
        if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            throw new SecurityTokenException("Invalid token");
        return principal;
    }

    //public void RemoveRefreshTokenByToken(string refreshToken)
    //{
    //    var user = _context.Users.FirstOrDefault(u => u.RefreshToken == refreshToken);
    //    if (user != null)
    //    {
    //        user.RefreshToken = null;
    //        _context.SaveChanges();
    //    }
    //    else
    //    {
    //        // Handle the case where the user is not found
    //        // You might want to throw an exception or log an error
    //    }
    //}
    //public void SaveRefreshToken(string userId, string refreshToken)
    //{
    //    // Implement database logic to save the refresh token for the user

    //    // Example using Entity Framework
    //    var user = _context.Users.FirstOrDefault(u => u.Id == userId);

    //    if (user != null)
    //    {
    //        // Update or add the refresh token for the user
    //        user.RefreshToken = refreshToken;

    //        // Save changes to the database
    //        _context.SaveChanges();
    //    }
    //    else
    //    {
    //        // Handle the case where the user is not found
    //        // You might want to throw an exception or log an error
    //    }

    //}

    ////public string GetUserToken(string userId)
    ////{
    ////    var user = _context.Users.FirstOrDefault(u => u.Id == userId);
    ////    if (user != null)
    ////    {
    ////        return GenerateToken(user);
    ////    }
    ////    else
    ////    {
    ////        // Handle the case where the user is not found
    ////        // You might want to throw an exception or log an error
    ////        return null;
    ////    }
    ////}

    //public string? GetRefreshToken(string userId)
    //{
    //    // Implement database logic to retrieve the refresh token for the user
    //    // Example using Entity Framework
    //    var user = _context.Users.FirstOrDefault(u => u.Id == userId);

    //    if (user != null)
    //    {
    //        return user.RefreshToken;
    //    }
    //    else
    //    {
    //        // Handle the case where the user is not found
    //        // You might want to throw an exception or log an error
    //        return null;
    //    }
    //}
    //public void RemoveRefreshToken(string userId)
    //{
    //    // Implement database logic to remove the refresh token for the user
    //    // Example using Entity Framework
    //    var user = _context.Users.FirstOrDefault(u => u.Id == userId);
    //    if (user != null)
    //    {
    //        user.RefreshToken = null;
    //        _context.SaveChanges();
    //    }
    //    else
    //    {
    //        // Handle the case where the user is not found
    //        // You might want to throw an exception or log an error
    //    }

    //}
}
