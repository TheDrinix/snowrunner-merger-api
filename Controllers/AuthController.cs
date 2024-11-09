using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Models.Auth.Dtos;
using SnowrunnerMergerApi.Services;
using SnowrunnerMergerApi.Services.Interfaces;

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
            
            var confirmationUrl = new Uri($"{Request.Headers.Origin}/auth/confirm-email?user-id={confirmationToken.UserId}&token={confirmationToken.Token}");
            
            await emailSender.SendEmailAsync(data.Email, "Verify your email", $"Please verify your email by clicking <a href=\"{confirmationUrl}\">here</a>.");

            return Created();
        }
        
        [HttpPost("refresh")]
        public async Task<ActionResult<LoginResponseDto>> RefreshToken()
        {
            var token = Request.Cookies["refresh_token"];
            
            if (string.IsNullOrEmpty(token)) return Unauthorized();
            
            var data = await authService.RefreshToken(token);
            
            return Ok(data);
        }
        
        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailDto data)
        {
            var verified = await authService.VerifyEmail(data.UserId, data.Token);

            return verified ? Ok() : BadRequest();
        }

        [HttpGet("google/signin")]
        public IActionResult GoogleSignin()
        {
            var credentials = authService.GetGoogleCredentials();
            
            var hashedState = authService.GenerateOauthStateToken();

            var redirectUrl = authService.GetGoogleCallbackUrl();
            
            var scopes = "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile";
            
            var url = new UriBuilder("https://accounts.google.com/o/oauth2/v2/auth")
            {
                Query = $"client_id={credentials.ClientId}&response_type=code&redirect_uri={redirectUrl}&scope={scopes}&include_granted_scopes=true&prompt=consent&state={hashedState}"
            }.ToString();
            
            return Ok(url);
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

            var redirectUrl = authService.GetGoogleCallbackUrl();

            var data = await authService.GoogleSignIn(code, redirectUrl);

            return Ok(data);
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await authService.Logout();
            
            return NoContent();
        }

        [HttpPost("resend-confirmation")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationDto body)
        {
            var confirmationToken = await authService.GenerateConfirmationToken(body.Email);
            
            if (confirmationToken is null)
            {
                return NoContent();
            }
            
            var confirmationUrl = new Uri($"{Request.Headers.Origin}/auth/confirm-email?user-id={confirmationToken.UserId}&token={confirmationToken.Token}");
            
            await emailSender.SendEmailAsync(body.Email, "Verify your email", $"Please verify your email by clicking <a href=\"{confirmationUrl}\">here</a>.");
            
            return NoContent();
        }

        [HttpPost("request-password-reset")]
        public async Task<IActionResult> RequestPasswordReset([FromBody] RequestResetPasswordDto body, [FromQuery] string? origin)
        {
            var resetToken = await authService.GeneratePasswordResetToken(body.Email);
            
            if (resetToken is null)
            {
                return NoContent();
            }
            
            if (string.IsNullOrEmpty(origin)) 
            {
                origin = Request.Headers.Origin;
            }
            
            var resetUrl = new Uri($"{origin}/auth/reset-password?user-id={resetToken.UserId}&token={resetToken.Token}");

            var html = $"""
                            <html>
                                <body>
                                    <h2>Password reset</h2>
                                    <p>
                                        Click <a href="{resetUrl}">here</a> to reset your password.
                                    </p>
                                    <p>The link will be valid for 30 minutes.</p>
                                    <p>If you did not request a password reset, please ignore this email.</p>
                                </body>
                            </html>
                        """;
            
            await emailSender.SendEmailAsync(body.Email, "Reset your password", html);
            
            return NoContent();
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto body)
        {
            await authService.ResetPassword(body);
            
            return Ok();
        }
    }
}
