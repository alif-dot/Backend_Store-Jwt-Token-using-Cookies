using Google.Apis.Auth;
using JWTAppYT.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace JWTAppYT.Controllers
{
    [Controller]
    public class AuthController : Controller
    {
        private static List<User> UserList = new List<User>();
        private readonly AppSettings _applicationSettings;
        private readonly HttpClient _httpClient;

        public AuthController(IOptions<AppSettings> _applicationSettings, HttpClient httpClient)
        {
            this._applicationSettings = _applicationSettings.Value;
            _httpClient = httpClient;
        }

        [HttpPost("Login")]
        public IActionResult Login([FromBody] Login model)
        {
            var user = UserList.Where(x => x.UserName == model.UserName).FirstOrDefault();

            if (user == null)
            {
                return BadRequest("Username Or Password Was Invalid");
            }

            var match = CheckPassword(model.Password, user);

            if (!match)
            {
                return BadRequest("Username Or Password Was Invalid");
            }

            var encrypterToken = JWTGenerator(user);

            return Ok(new { token = encrypterToken, username = user.UserName });
        }

        public dynamic JWTGenerator(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(this._applicationSettings.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", user.UserName), new Claim(ClaimTypes.Role, user.Role),
                        new Claim(ClaimTypes.DateOfBirth, user.BirthDay)}),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var encrypterToken = tokenHandler.WriteToken(token);

            SetJWT(encrypterToken);

            var refreshToken = GenerateRefreshToken();

            SetRefreshToken(refreshToken, user);

            return new { token = encrypterToken, username = user.UserName };
        }

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken()
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7),
                Created = DateTime.Now
            };

            return refreshToken;

        }

        [HttpGet("RefreshToken")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["X-Refresh-Token"];

            var user = UserList.Where(x => x.Token == refreshToken).FirstOrDefault();

            if (user == null || user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token has expired");
            }

            JWTGenerator(user);

            return Ok();
        }

        public void SetRefreshToken(RefreshToken refreshToken, User user)
        {

            HttpContext.Response.Cookies.Append("X-Refresh-Token", refreshToken.Token,
                 new CookieOptions
                 {
                     Expires = refreshToken.Expires,
                     HttpOnly = true,
                     Secure = true,
                     IsEssential = true,
                     SameSite = SameSiteMode.None
                 });

            UserList.Where(x => x.UserName == user.UserName).First().Token = refreshToken.Token;
            UserList.Where(x => x.UserName == user.UserName).First().TokenCreated = refreshToken.Created;
            UserList.Where(x => x.UserName == user.UserName).First().TokenExpires = refreshToken.Expires;
        }

        public void SetJWT(string encrypterToken)
        {

            HttpContext.Response.Cookies.Append("X-Access-Token", encrypterToken,
                  new CookieOptions
                  {
                      Expires = DateTime.Now.AddMinutes(5),
                      HttpOnly = true,
                      Secure = true,
                      IsEssential = true,
                      SameSite = SameSiteMode.None
                  });
        }

        [HttpDelete("RevokeToken/{username}")]
        public async Task<IActionResult> RevokeToken(string username)
        {

            var user = UserList.FirstOrDefault(x => x.UserName == username);

            if (user != null)
            {
                user.Token = "";
                return Ok();
            }

            return NotFound();
        }


        [HttpPost("LoginWithGoogle")]
        public async Task<IActionResult> LoginWithGoogle([FromBody] string credential)
        {
            var settings = new GoogleJsonWebSignature.ValidationSettings()
            {
                Audience = new List<string> { this._applicationSettings.GoogleClientId }
            };

            var payload = await GoogleJsonWebSignature.ValidateAsync(credential, settings);

            var user = UserList.Where(x => x.UserName == payload.Name).FirstOrDefault();

            if (user != null)
            {
                return Ok(JWTGenerator(user));
            }
            else
            {
                return BadRequest();
            }
        }

        [HttpPost("LoginWithFacebook")]
        public async Task<IActionResult> LoginWithFacebook([FromBody] string credential)
        {
            HttpResponseMessage debugTokenResponse = await _httpClient.GetAsync("https://graph.facebook.com/debug_token?input_token=" + credential + $"&access_token={this._applicationSettings.FacebookAppId}|{this._applicationSettings.FacebookSecret}");

            var stringThing = await debugTokenResponse.Content.ReadAsStringAsync();
            var userOBJK = JsonConvert.DeserializeObject<FBUser>(stringThing);

            if (userOBJK.Data.IsValid == false)
            {
                return Unauthorized();
            }

            HttpResponseMessage meResponse = await _httpClient.GetAsync("https://graph.facebook.com/me?fields=first_name,last_name,email,id&access_token=" + credential);
            var userContent = await meResponse.Content.ReadAsStringAsync();
            var userContentObj = JsonConvert.DeserializeObject<FBUserInfo>(userContent);

            var user = UserList.Where(x => x.UserName == userContentObj.Email).FirstOrDefault();

            if (user != null)
            {
                return Ok(JWTGenerator(user));
            }
            else
            {
                return BadRequest();
            }
        }

        private bool CheckPassword(string password, User user)
        {
            bool result;

            using (HMACSHA512? hmac = new HMACSHA512(user.PasswordSalt))
            {
                var compute = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                result = compute.SequenceEqual(user.PasswordHash);
            }

            return result;
        }

        [HttpPost("Register")]
        public IActionResult Register([FromBody] Register model)
        {
            var user = new User { UserName = model.UserName, Role = model.Role, BirthDay = model.BirthDay };

            if(model.ConfirmPassword == model.Password)
            {
                using (HMACSHA512? hmac = new HMACSHA512())
                {
                    user.PasswordSalt = hmac.Key;
                    user.PasswordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(model.Password));
                }
            }
            else
            {
                return BadRequest("Passwords Dont Match");
            }

            UserList.Add(user);

            return Ok(user);
        }
    }
}
