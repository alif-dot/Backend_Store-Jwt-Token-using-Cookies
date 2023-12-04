using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;


namespace JWTAppYT.Controllers
{
    [Authorize]
    [ApiController]
    public class ItemsController : Controller
    {
        private readonly AppSettings _applicationSettings;

        public ItemsController(IOptions<AppSettings> applicationSettings)
        {
            _applicationSettings = applicationSettings.Value;
        }

        public List<string> colorList = new List<string>() { "blue", "red", "green", "yellow", "pink" };

        [HttpGet("GetColorList")]
        public IActionResult GetColorList()
        {
            //try
            //{
            //    return colorList;
            //}
            //catch (Exception ex)
            //{
            //    throw;
            //}

            try
            {
                if (!HttpContext.Request.Headers.ContainsKey("Authorization"))
                {
                    return Unauthorized("Authorization header is missing.");
                }

                var authorizationHeader = HttpContext.Request.Headers["Authorization"].ToString();

                if (!authorizationHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Invalid authorization header format.");
                }

                var token = authorizationHeader.Substring("Bearer ".Length);

                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_applicationSettings.Secret);

                try
                {
                    tokenHandler.ValidateToken(token, new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ClockSkew = TimeSpan.Zero
                    }, out _);
                }
                catch (SecurityTokenException)
                {
                    return Unauthorized("Invalid token.");
                }

                return Ok(colorList);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return StatusCode(500, "Internal server error");
            }
        }
    }
}
