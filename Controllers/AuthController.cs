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
    public class AuthController(IAuthService authService, IEmailSender emailSender) : ControllerBase
    {
        [HttpPost("login")]
        public async Task<ActionResult<LoginResponseDto>> Login([FromBody] LoginDto data)
        {
            return Ok(await authService.Login(data));
        }
        
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto data)
        {
            var confirmationToken = await authService.Register(data);
            
            var confirmationUrl = new Uri($"{Request.Scheme}://{Request.Host}/confirm-email?user-id={confirmationToken.UserId}&token={confirmationToken.Token}");
            
            await emailSender.SendEmailAsync(data.Email, "Verify your email", $"Please verify your email by clicking <a href=\"{confirmationUrl}\">here</a>.");

            return Created();
        }
        
        [HttpPost("refresh")]
        public async Task<LoginResponseDto> RefreshToken([FromBody] string token)
        {
            return await authService.RefreshToken(token);
        }
        
        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmail([FromBody] Guid userId, [FromBody] string token)
        {
            var verified = await authService.VerifyEmail(userId, token);

            return verified ? Ok() : BadRequest();
        }

        [HttpGet("google/signin")]
        public IActionResult GoogleSignin()
        {
            var credentials = authService.GetGoogleCredentials();
            
            var state = authService.GenerateOauthStateToken();
            
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
            if (!authService.ValidateOauthStateToken(state))
            {
                return BadRequest();
            }            
            
            if (!string.IsNullOrEmpty(error))
            {
                return BadRequest();
            }
            
            var redirectUrl = Url.Action(nameof(GoogleSigninCallback), "Auth", null, Request.Scheme);

            var data = await authService.GoogleSignIn(code, redirectUrl.ToLower());

            return Ok(data);
        }
    }
}
