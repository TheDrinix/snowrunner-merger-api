using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Models.Auth.Dtos;
using SnowrunnerMergerApi.Services;

namespace SnowrunnerMergerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }
        
        [HttpPost("login")]
        public async Task<LoginResponseDto> Login([FromBody] LoginDto data)
        {
            return await _authService.Login(data);
        }
        
        [HttpPost("register")]
        public async Task<User> Register([FromBody] RegisterDto data)
        {
            return await _authService.Register(data);
        }
        
        [HttpPost("refresh")]
        public async Task<LoginResponseDto> RefreshToken([FromBody] string token)
        {
            return await _authService.RefreshToken(token);
        }

        [HttpGet("google/signin")]
        public IActionResult GoogleSignin()
        {
            var credentials = _authService.GetGoogleCredentials();
            
            var state = _authService.GenerateOauthStateToken();
            
            var redirectUrl = Url.Action(nameof(GoogleSigninCallback), "Auth", null, Request.Scheme);
            
            var scopes = "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile";
            
            var url = new UriBuilder("https://accounts.google.com/o/oauth2/v2/auth")
            {
                Query = $"client_id={credentials.ClientId}&response_type=code&redirect_uri={redirectUrl.ToLower()}&scope={scopes}&include_granted_scopes=true&prompt=consent&state={state}"
            }.ToString();
            
            return Redirect(url);
        }
        
        [HttpGet("google/signin/callback")]
        public async Task<IActionResult> GoogleSigninCallback(string? code, string state, string? error)
        {
            if (!_authService.ValidateOauthStateToken(state))
            {
                return BadRequest();
            }            
            
            if (!string.IsNullOrEmpty(error))
            {
                return BadRequest();
            }
            
            var redirectUrl = Url.Action(nameof(GoogleSigninCallback), "Auth", null, Request.Scheme);

            var data = await _authService.GoogleSignIn(code, redirectUrl.ToLower());

            return Ok(data);
        }
    }
}
