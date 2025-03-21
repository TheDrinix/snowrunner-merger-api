using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SnowrunnerMergerApi.Models.Auth.Dtos;
using SnowrunnerMergerApi.Services;
using SnowrunnerMergerApi.Services.Interfaces;
using Swashbuckle.AspNetCore.Annotations;
using System.Net;
using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Models.Auth.Google;

namespace SnowrunnerMergerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService, IUserService userService, IEmailSender emailSender) : ControllerBase
    {
        [HttpPost("login")]
        [SwaggerOperation(Summary = "Logs in a user", Description = "Logs in a user with provided credentials and returns a JWT token")]
        [SwaggerResponse(StatusCodes.Status200OK, "Logs in successfully", typeof(LoginResponseDto))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid request body")]
        [SwaggerResponse(StatusCodes.Status401Unauthorized, "Invalid credentials")]
        [SwaggerResponse(StatusCodes.Status403Forbidden, "Email not verified")]
        public async Task<ActionResult<LoginResponseDto>> Login([FromBody] LoginDto data)
        {
            return Ok(await authService.Login(data));
        }
        
        [HttpPost("register")]
        [SwaggerOperation(Summary = "Registers a new user", Description = "Registers a new user with provided details and sends a confirmation email")]
        [SwaggerResponse(StatusCodes.Status201Created, "User registered successfully")]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid request body or password requirements not met")]
        [SwaggerResponse(StatusCodes.Status409Conflict, "User with email already exists")]
        public async Task<IActionResult> Register([FromBody] RegisterDto data)
        {
            var confirmationToken = await authService.Register(data);
            
            var confirmationUrl = new Uri($"{Request.Headers.Origin}/auth/confirm-email?token={WebUtility.UrlEncode(confirmationToken.Token)}");
            
            var html = $"""
                        <html>
                            <body>        
                                <h2>Verify your email</h2>
                                <p>
                                    Please verify your email by clicking <a href="{confirmationUrl}">here</a>.
                                </p>
                                <p>The link will be valid for an hour.</p>
                                <p>If you did not register, please ignore this email.</p>
                            </body>
                        </html>
                      """;
            
            await emailSender.SendEmailAsync(data.Email, "Verify your email", html);

            return Created();
        }

        [HttpGet("refresh")]
        [SwaggerOperation(Summary = "Gets long-lived refresh token", Description = "Gets long-lived refresh token for a user to use in frontend (desktop app)")]
        [SwaggerResponse(StatusCodes.Status200OK, "Refresh token retrieved successfully", typeof(RefreshTokenDto))]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        [Authorize]
        public async Task<ActionResult<RefreshTokenDto>> GetLongLivedRefreshToken()
        {
            var userData = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            
            if (userData is null) return Unauthorized();
            
            var data = await authService.GetLongLivedRefreshToken(Guid.Parse(userData));
            
            return Ok(data);
        }
        
        [HttpPost("refresh")]
        [SwaggerOperation(Summary = "Refreshes JWT token", Description = "Refreshes JWT token using refresh token")]
        [SwaggerResponse(StatusCodes.Status200OK, "Token refreshed successfully", typeof(RefreshResponseDto))]
        [SwaggerResponse(StatusCodes.Status401Unauthorized, "Invalid refresh token")]
        public async Task<ActionResult<RefreshResponseDto>> RefreshToken(RefreshDto body)
        {
            var isCookieToken = body.Token is null;
            var token = body.Token ?? Request.Cookies["refresh_token"];
            
            if (string.IsNullOrEmpty(token)) return Unauthorized();
            
            var data = await authService.RefreshToken(token, isCookieToken);
            
            return Ok(data);
        }
        
        [HttpPost("verify-email")]
        [SwaggerOperation(Summary = "Verifies user's email", Description = "Verifies user's email using provided token")]
        [SwaggerResponse(StatusCodes.Status200OK, "Email verified successfully")]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid token")]
        public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailDto data)
        {
            var verified = await authService.VerifyEmail(data.Token);

            return verified ? Ok() : BadRequest();
        }

        [HttpGet("google/signin")]
        [SwaggerOperation(Summary = "Initiates Google sign-in", Description = "Initiates Google sign-in flow")]
        [SwaggerResponse(StatusCodes.Status200OK, "Returns google signin url", typeof(string))]
        public IActionResult GoogleSignin([FromQuery] string? callbackUrl)
        {
            var credentials = authService.GetGoogleCredentials();
            
            var hashedState = authService.GenerateOauthStateToken();

            var redirectUrl = callbackUrl ?? authService.GetGoogleCallbackUrl();
            
            const string scopes = "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile";
            
            var url = new UriBuilder("https://accounts.google.com/o/oauth2/v2/auth")
            {
                Query = $"client_id={credentials.ClientId}&response_type=code&redirect_uri={redirectUrl}&scope={scopes}&include_granted_scopes=true&prompt=consent&state={WebUtility.UrlEncode(hashedState)}"
            }.ToString();
            
            return Ok(url);
        }
        
        [HttpGet("google/signin/callback")]
        [SwaggerOperation(Summary = "Handles Google sign-in callback", Description = "Handles Google sign-in callback and returns JWT token")]
        [SwaggerResponse(StatusCodes.Status200OK, "Sign-in successful", typeof(LoginResponseDto))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid state token or error during google sign-in")]
        public async Task<IActionResult> GoogleSigninCallback(string? code, string state, string? error, string? callbackUrl)
        {
            if (!authService.ValidateOauthStateToken(state))
            {
                return BadRequest();
            }            
            
            if (!string.IsNullOrEmpty(error))
            {
                return BadRequest();
            }

            var redirectUrl = callbackUrl ?? authService.GetGoogleCallbackUrl();

            var res = await authService.GoogleSignIn(code!, redirectUrl);

            return res switch
            {
                GoogleSignInResult.GoogleSignInAccountSetupRequired googleSignInAccountSetupRequired => Ok(new
                {
                    tokenType = GoogleResTokenType.CompletionToken,
                    data = googleSignInAccountSetupRequired.completionToken
                }),
                GoogleSignInResult.GoogleSignInLinkRequired googleSignInLinkRequired => Ok(new
                {
                    tokenType = GoogleResTokenType.LinkingToken,
                    data = googleSignInLinkRequired.linkingToken,  
                }),
                GoogleSignInResult.GoogleSignInSuccess googleSignInSuccess => Ok(new
                {
                    tokenType = GoogleResTokenType.AccessToken,
                    data = googleSignInSuccess.data
                }),
                _ => StatusCode(500)
            };
        }

        [HttpGet("google/link/callback")]
        [Authorize]
        [SwaggerOperation(Summary = "Handles Google account linking callback", Description = "Handles Google account linking callback and links Google account to the current user")]
        [SwaggerResponse(StatusCodes.Status200OK, "Account linked successfully", typeof(User))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid state token or error during google account linking")]
        [SwaggerResponse(StatusCodes.Status409Conflict, "There is already a user with the Google account linked")]
        public async Task<IActionResult> LinkGoogleAccountCallback(string? code, string state, string? error,
            string callbackUrl)
        {
            if (!string.IsNullOrEmpty(error))
            {
                return BadRequest();
            }
            
            if (!authService.ValidateOauthStateToken(state))
            {
                return BadRequest();
            }

            var user = await userService.GetCurrentUser();

            var updatedUser = await authService.LinkGoogleAccount(user, code!, callbackUrl);

            return Ok(updatedUser);
        }

        [HttpPost("google/link-account")]
        [SwaggerOperation(Summary = "Links Google account", Description = "Links Google account to an existing user account")]
        [SwaggerResponse(StatusCodes.Status200OK, "Account linked successfully and logs user in", typeof(LoginResponseDto))]
        [SwaggerResponse(StatusCodes.Status401Unauthorized, "Invalid or expired linking token")]
        public async Task<IActionResult> LinkAccount([FromBody] LinkAccountDto data)
        {
            var accessTokenData = await authService.LinkGoogleAccount(data.LinkingToken);
            
            return Ok(accessTokenData);
        }
        
        [HttpPost("google/finish-account-setup")]
        [SwaggerOperation(Summary = "Finishes Google account setup", Description = "Finishes Google account setup for a new user")]
        [SwaggerResponse(StatusCodes.Status200OK, "Account setup finished successfully and logs user in", typeof(LoginResponseDto))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid account data or password requirements not met")]
        [SwaggerResponse(StatusCodes.Status401Unauthorized, "Invalid or expired account completion token")]
        public async Task<IActionResult> FinishAccountSetup([FromBody] FinishAccountSetupDto data)
        {
            var accessTokenData = await authService.FinishAccountSetup(data);
            
            return Ok(accessTokenData);
        }
        
        [HttpPost("google/unlink")]
        [Authorize]
        [SwaggerOperation(Summary = "Unlinks Google account", Description = "Unlinks Google account from the current user")]
        [SwaggerResponse(StatusCodes.Status204NoContent, "Account unlinked successfully")]
        public async Task<IActionResult> UnlinkGoogleAccount()
        {
            await authService.UnlinkGoogleAccount();
            
            return NoContent();
        }

        [HttpPost("logout")]
        [Authorize]
        [SwaggerOperation(Summary = "Logs out a user", Description = "Logs out a user and invalidates refresh token")]
        [SwaggerResponse(StatusCodes.Status204NoContent, "Logged out successfully")]
        public async Task<IActionResult> Logout()
        {
            await authService.Logout();
            
            return NoContent();
        }

        [HttpPost("resend-confirmation")]
        [SwaggerOperation(Summary = "Resends confirmation email", Description = "Resends confirmation email to user")]
        [SwaggerResponse(StatusCodes.Status204NoContent, "Email was sent if a user with provided email exists")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationDto body)
        {
            var confirmationToken = await authService.GenerateConfirmationToken(body.Email);
            
            if (confirmationToken is null)
            {
                return NoContent();
            }
            
            var confirmationUrl = new Uri($"{Request.Headers.Origin}/auth/confirm-email?token={WebUtility.UrlEncode(confirmationToken.Token)}");
            
            var html = $"""
                          <html>
                              <body>        
                                  <h2>Verify your email</h2>
                                  <p>
                                      Please verify your email by clicking <a href="{confirmationUrl}">here</a>.
                                  </p>
                                  <p>The link will be valid for an hour.</p>
                                  <p>If you did not register, please ignore this email.</p>
                              </body>
                          </html>
                        """;
            
            await emailSender.SendEmailAsync(body.Email, "Verify your email", html);
            
            return NoContent();
        }

        [HttpPost("request-password-reset")]
        [SwaggerOperation(Summary = "Requests password reset", Description = "Requests password reset and sends an email with reset link")]
        [SwaggerResponse(StatusCodes.Status204NoContent, "Email was sent if a user with provided email exists")]
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
            
            var resetUrl = new Uri($"{origin}/auth/reset-password?token={WebUtility.UrlEncode(resetToken.Token)}");

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
        [SwaggerOperation(Summary = "Resets user's password", Description = "Resets user's password using provided token")]
        [SwaggerResponse(StatusCodes.Status200OK, "Password reset successfully")]
        [SwaggerResponse(StatusCodes.Status401Unauthorized, "Invalid token")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto body)
        {
            await authService.ResetPassword(body);
            
            return Ok();
        }
    }
}
