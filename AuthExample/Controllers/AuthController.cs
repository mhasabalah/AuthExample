using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthExample.Controllers;

[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly JwtOptions _jwtSettings;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        RoleManager<IdentityRole> roleManager,
        IOptions<JwtOptions> jwtSettings)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
        _jwtSettings = jwtSettings.Value;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] UserLoginDto user)
    {
        // User validation logic here
        var userIsValid = ValidateUser(user);

        if (!userIsValid)
        {
            return Unauthorized();
        }

        var token = GenerateJwtToken(user);
        //_signInManager.SignInAsync(user, true);
        return Ok(token);
    }

    public string GenerateJwtToken(IEnumerable<Claim> claims)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret); 

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private async Task<IEnumerable<Claim>> CreateClaims(ApplicationUser? loggedinUser)
    {
        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, loggedinUser.UserName ?? ""),
            new Claim(ClaimTypes.Email, loggedinUser.Email ?? ""),
            new Claim(ClaimTypes.NameIdentifier, loggedinUser.Id.ToString()),
        };
        var userRoles = await _userManager.GetRolesAsync(loggedinUser);
        foreach (var userRole in userRoles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, userRole));
        }
        return authClaims;
    }

    //private bool ValidateUser(UserLoginDto user)
    //{
    //    // check if user exists in database and if password is correct
    //    User? dbSystemUser = (await.Read()).FirstOrDefault(e => e.Email == loginRequest.Email && e.Password == loginRequest.Password) ?? new();






    //}
}


public class UserLoginDto
{
    public string Name { get; set; }
    public string Password { get; set; }
}