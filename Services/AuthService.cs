﻿using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NuGet.Protocol;
using SnowrunnerMergerApi.Data;
using SnowrunnerMergerApi.Exceptions;
using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Models.Auth.Dtos;
using SnowrunnerMergerApi.Models.Auth.Google;
using SnowrunnerMergerApi.Models.Auth.Tokens;
using SnowrunnerMergerApi.Services.Interfaces;
using SameSiteMode = Microsoft.AspNetCore.Http.SameSiteMode;

namespace SnowrunnerMergerApi.Services;

public class AuthService : IAuthService
{
    private readonly ILogger<AuthService> _logger;
    private readonly AppDbContext _dbContext;
    private readonly IConfiguration _config;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly HttpClient _httpClient;
    private readonly IWebHostEnvironment _webHostEnvironment;
    private readonly SameSiteMode _sameSiteMode = SameSiteMode.Lax;
    private readonly int _maxRetries = 5;

    private const int AccessTokenLifetime = 60 * 60 * 3; // 3 hours

    public AuthService(
        ILogger<AuthService> logger,
        AppDbContext dbContext,
        IConfiguration config,
        IHttpContextAccessor httpContextAccessor,
        IWebHostEnvironment webHostEnvironment
    )
    {
        _logger = logger;
        _dbContext = dbContext;
        _config = config;
        _httpContextAccessor = httpContextAccessor;
        _webHostEnvironment = webHostEnvironment;
        _httpClient = new HttpClient
        {
            BaseAddress = new Uri("https://www.googleapis.com")
        };

        if (_webHostEnvironment.IsDevelopment())
        {
            _sameSiteMode = SameSiteMode.None;
        }
    }

    /// <summary>
    /// Registers a new user using the provided data.
    /// </summary>
    /// <param name="data">A <see cref="RegisterDto"/> object containing the user's registration details.</param>
    /// <returns>A <see cref="AccountConfirmationToken"/> object containing the confirmation token for the user.</returns>
    /// <exception cref="HttpResponseException">
    /// Thrown with different HTTP status codes depending on the validation failure:
    /// <list type="bullet">
    ///     <item>
    ///         HttpStatusCode.BadRequest (400): If the password does not meet the validation criteria.
    ///     </item>
    ///     <item>
    ///         HttpStatusCode.Conflict (409): If the email is already in use.
    ///     </item>
    /// </list>
    /// </exception>
    public async Task<AccountConfirmationToken> Register(RegisterDto data)
    {
        var passwordErrors = ValidatePassword(data.Password);
        if (passwordErrors.Count > 0)
        {
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Invalid password", new Dictionary<string, object> {{"password", passwordErrors}});
        }
        
        var normalizedEmail = data.Email.ToUpper();
        var normalizedUsername = data.Username.ToUpper();

        var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail);
        if (user is not null)
        {
            throw new HttpResponseException(HttpStatusCode.Conflict, "Email already in use");
        }

        var salt = new byte[128 / 8];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        
        user = new User()
        {
            Email = data.Email,
            NormalizedEmail = normalizedEmail,
            Username = data.Username,
            NormalizedUsername = normalizedUsername,
            PasswordHash = HashPassword(data.Password, salt),
            PasswordSalt = salt,
            CreatedAt = DateTime.UtcNow,
            EmailConfirmed = false
        };

        await _dbContext.Users.AddAsync(user);
        // await _dbContext.SaveChangesAsync();

        var userConfirmationToken = await GenerateConfirmationToken(user);

        return userConfirmationToken;
    }
    
    /// <summary>
    /// Attempts to log in a user with the provided credentials.
    /// </summary>
    /// <param name="data">A <see cref="LoginDto"/> object containing the user's email and password.</param>
    /// <returns>A <see cref="LoginResponseDto"/> object containing the access token, expiration time, and user information on success.</returns>
    /// <exception cref="HttpResponseException">
    /// Thrown with different HTTP status codes depending on the validation failure:
    /// <list type="bullet">
    ///     <item>
    ///         HttpStatusCode.Unauthorized (401):
    ///         <list type="bullet">
    ///             <item>
    ///                 If the user email is not found in the database.
    ///             </item>
    ///             <item>
    ///                 If the provided password is incorrect.
    ///             </item>
    ///         </list>
    ///     </item>
    ///     <item>
    ///         HttpStatusCode.Forbidden (403): If the user's email is not confirmed.
    ///     </item>
    /// </list>
    /// </exception>
    public async Task<LoginResponseDto> Login(LoginDto data)
    {
        var user = await _dbContext.Users
            .FirstOrDefaultAsync(u => u.NormalizedEmail == data.Email.ToUpper());
        
        if (user is null)
        {
            throw new HttpResponseException(HttpStatusCode.Unauthorized, "Invalid email or password");
        }

        if (!VerifyPassword(user, data.Password))
        {
            throw new HttpResponseException(HttpStatusCode.Unauthorized, "Invalid email or password");
        }
        
        if (!user.EmailConfirmed)
        {
            throw new HttpResponseException(HttpStatusCode.Forbidden, "Email not confirmed");
        }

        var refreshTokenData = await GenerateRefreshToken(user);
        
        var token = GenerateJwt(new JwtData()
        {
            Id = user.Id, 
            Username = user.Username, 
            Email = user.Email,
            SessionId = refreshTokenData.Session.Id
        });
        
        return new LoginResponseDto
        {
            AccessToken = token,
            ExpiresIn = AccessTokenLifetime,
            User = user
        };
    }
    
    /// <summary>
    ///  Attempts to refresh the access token using the provided refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token used to generate a new access token.</param>
    /// <param name="isCookieToken">A boolean indicating whether the refresh token is stored in a cookie.</param>
    /// <returns>A <see cref="RefreshResponseDto"/> object containing the new access token, expiration time, and user information on success.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with an HTTP status code of HttpStatusCode.Unauthorized (401) if the refresh token is invalid.
    /// </exception>
    public async Task<RefreshResponseDto> RefreshToken(string refreshToken, bool isCookieToken = true)
    {
        var refreshTokenData = await ValidateRefreshToken(refreshToken);
        
        if (refreshTokenData is null)
        {
            throw new HttpResponseException(HttpStatusCode.Unauthorized);
        }
        
        var session = refreshTokenData.Session;
        
        if (isCookieToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = _sameSiteMode,
                Expires = session.ExpiresAt,
                Path = "/api/auth/refresh"
            };

            _httpContextAccessor.HttpContext?.Response.Cookies.Append("refresh_token", refreshTokenData.Token, cookieOptions);
        }
        
        var token = GenerateJwt(new JwtData()
        {
            Id = session.User.Id, 
            Username = session.User.Username, 
            Email = session.User.Email,
            SessionId = session.Id
        });


        return new RefreshResponseDto()
        {
            AccessToken = token,
            ExpiresIn = AccessTokenLifetime,
            User = session.User,
            RefreshToken = isCookieToken ? null : refreshTokenData.Token
        };
    }

    /// <summary>
    ///     Retrieves a long-lived refresh token for the user.
    /// </summary>
    /// <param name="userId">The ID of the user to generate the refresh token for.</param>
    /// <returns>A <see cref="RefreshTokenDto"/> object containing the long-lived refresh token and expiration time on success.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with an HTTP status code of HttpStatusCode.Unauthorized (401) if the user is not found (is not authorized).
    /// </exception>
    public async Task<RefreshTokenDto> GetLongLivedRefreshToken(Guid userId)
    {
        var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
        
        if (user is null)
        {
            throw new HttpResponseException(HttpStatusCode.Unauthorized);
        }

        var refreshTokenData = await GenerateRefreshToken(user, true, false);
        
        return new RefreshTokenDto
        {
            Token = refreshTokenData.Token,
            ExpiresAt = refreshTokenData.Session.ExpiresAt
        };
    }
    
    /// <summary>
    ///     Retrieves the Google OAuth2 credentials from the configuration.
    /// </summary>
    /// <returns>A <see cref="GoogleCredentials"/> object containing the Google OAuth2 client ID and secret.</returns>
    public GoogleCredentials GetGoogleCredentials()
    {
        var googleCredentials = _config.GetSection("Authentication:Google").Get<GoogleCredentials>();
        
        if (googleCredentials is null)
        {
            _logger.LogError("Google credentials not found");
            throw new ArgumentNullException(nameof(googleCredentials));
        }
        
        return googleCredentials;
    }

    /// <summary>
    ///     Attempts to sign in a user using the provided Google OAuth2 code.
    ///     If the user does not exist, a new user is created.
    /// </summary>
    /// <param name="code">The Google OAuth2 code used to exchange for an access token.</param>
    /// <param name="redirectUri">The redirect URI used to exchange the code.</param>
    /// <returns>A <see cref="LoginResponseDto"/> object containing the access token, expiration time, and user information on success.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with an HTTP status code of HttpStatusCode.BadRequest (400) if the access token or user data is invalid.
    /// </exception>
    public async Task<GoogleSignInResult> GoogleSignIn(string code, string redirectUri)
    {
        var userData = await GetGoogleAccountData(code, redirectUri);
        
        var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.GoogleId == userData.Id);
        
        if (user is null)
        {
            user = await _dbContext.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == userData.Email.ToUpper());

            if (user is not null)
            {
                if (user.GoogleId is not null)
                {
                    throw new HttpResponseException(HttpStatusCode.Conflict, "There's a different google account linked to this email");
                }
                
                var accountLinkingToken = await GenerateLinkingToken(user, userData.Id);
                
                return new GoogleSignInResult.GoogleSignInLinkRequired(accountLinkingToken);
            }

            var accountCompletionToken = await GenerateCompletionToken(userData.Email, userData.Id);
            
            return new GoogleSignInResult.GoogleSignInAccountSetupRequired(accountCompletionToken);
        }
        
        if (!user.EmailConfirmed)
        {
            user.EmailConfirmed = true;
            _dbContext.Users.Update(user);
            await _dbContext.SaveChangesAsync();
        }

        var refreshTokenData = await GenerateRefreshToken(user);
        
        var token = GenerateJwt(new JwtData()
        {
            Id = user.Id, 
            Username = user.Username, 
            Email = user.Email,
            SessionId = refreshTokenData.Session.Id
        });

        return new GoogleSignInResult.GoogleSignInSuccess(new LoginResponseDto
        {
            AccessToken = token,
            ExpiresIn = AccessTokenLifetime,
            User = user
        });
    }

    /// <summary>
    ///     Attempts to link a Google account to an existing account.
    ///     User gets signed in if the linking is successful.
    /// </summary>
    /// <param name="linkingToken">The linking token used to link the Google account.</param>
    /// <returns>A <see cref="LoginResponseDto"/> object containing the access token, expiration time, and user information on success.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with different HTTP status codes depending on the validation failure:
    ///     <list type="bullet">
    ///         <item>
    ///             HttpStatusCode.BadRequest (400): If the Google account is already linked to another user.
    ///         </item>
    ///         <item>
    ///             HttpStatusCode.Unauthorized (401): If the linking token is invalid or expired.
    ///         </item>
    ///         <item>
    ///             HttpStatusCode.Conflict (409): If the user already has a linked Google account.
    ///         </item>
    ///     </list>
    /// </exception>
    public async Task<LoginResponseDto> LinkGoogleAccount(string linkingToken)
    {
        var linkingTokenEntry = await _dbContext.UserTokens
            .OfType<AccountLinkingToken>()
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.Token == linkingToken);

        if (linkingTokenEntry is null || linkingTokenEntry.ExpiresAt < DateTime.UtcNow)
        {
            throw new HttpResponseException(HttpStatusCode.Unauthorized);
        }
        
        _dbContext.UserTokens.Remove(linkingTokenEntry);
        var user = await LinkGoogleAccount(linkingTokenEntry.GoogleId, linkingTokenEntry.User);
        
        var refreshTokenData = await GenerateRefreshToken(user);
        
        var token = GenerateJwt(new JwtData()
        {
            Id = user.Id, 
            Username = user.Username, 
            Email = user.Email,
            SessionId = refreshTokenData.Session.Id
        });
        
        return new LoginResponseDto
        {
            AccessToken = token,
            ExpiresIn = AccessTokenLifetime,
            User = user
        };
    }

    /// <summary>
    ///     Attempts to link a Google account to an existing account using the provided Google OAuth2 code.
    /// </summary>
    /// <param name="user">The user to link the Google account to.</param>
    /// <param name="code">The Google OAuth2 code used to exchange for an access token.</param>
    /// <param name="redirectUri">The OAuth redirect url.</param>
    /// <returns>The updated user.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with different HTTP status codes depending on the validation failure:
    ///     <list type="bullet">
    ///         <item>
    ///             HttpStatusCode.BadRequest (400): If the Google account is already linked to another user
    ///             or there was an error trying to receive the google account data.
    ///         </item>
    ///         <item>
    ///             HttpStatusCode.Conflict (409): If the user already has a linked Google account.
    ///         </item>
    ///     </list>
    /// </exception>
    public async Task<User> LinkGoogleAccount(User user, string code, string redirectUri)
    {
        var googleData = await GetGoogleAccountData(code, redirectUri);

        if (googleData is null)
        {
            throw new HttpResponseException(HttpStatusCode.BadRequest);
        }

        return await LinkGoogleAccount(googleData.Id, user);
    }
    

    /// <summary>
    ///     Attempts to finish the account for a user using the provided data.
    ///     User gets signed in if the account setup is successful.
    /// </summary>
    /// <param name="data">A <see cref="FinishAccountSetupDto"/> object containing the user's account details.</param>
    /// <returns>A <see cref="LoginResponseDto"/> object containing the access token, expiration time, and user information on success.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with different HTTP status codes depending on the validation failure:
    ///     <list type="bullet">
    ///         <item>
    ///             HttpStatusCode.Unauthorized (401): If the completion token is invalid or expired.
    ///         </item>
    ///         <item>
    ///             HttpStatusCode.BadRequest (400): If the password does not meet the validation criteria.
    ///         </item>
    ///     </list>
    /// </exception>
    public async Task<LoginResponseDto> FinishAccountSetup(FinishAccountSetupDto data)
    {
        var completionTokenEntry = await _dbContext.UserTokens
            .OfType<AccountCompletionToken>()
            .FirstOrDefaultAsync(t => t.Token == data.CompletionToken);
        
        if (completionTokenEntry is null || completionTokenEntry.ExpiresAt < DateTime.UtcNow)
        {
            throw new HttpResponseException(HttpStatusCode.Unauthorized);
        }
        
        var passwordErrors = ValidatePassword(data.Password);
        
        if (passwordErrors.Count > 0)
        {
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Invalid password", new Dictionary<string, object> {{"password", passwordErrors}});
        }
        
        var passwordSalt = new byte[128 / 8];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(passwordSalt);
        }
        
        var user = new User
        {
            Email = completionTokenEntry.Email,
            GoogleId = completionTokenEntry.GoogleId,
            Username = data.Username,
            NormalizedUsername = data.Username.ToUpper(),
            NormalizedEmail = completionTokenEntry.Email.ToUpper(),
            PasswordHash = HashPassword(data.Password, passwordSalt),
            PasswordSalt = passwordSalt,
            CreatedAt = DateTime.UtcNow,
            EmailConfirmed = true
        };
        
        _dbContext.Users.Add(user);
        _dbContext.UserTokens.Remove(completionTokenEntry);
        
        await _dbContext.SaveChangesAsync();
        
        var refreshTokenData = await GenerateRefreshToken(user);
        
        var token = GenerateJwt(new JwtData()
        {
            Id = user.Id, 
            Username = user.Username, 
            Email = user.Email,
            SessionId = refreshTokenData.Session.Id
        });

        return new LoginResponseDto()
        {
            AccessToken = token,
            ExpiresIn = AccessTokenLifetime,
            User = user
        };
    }

    /// <summary>
    ///     Attempts to unlink the Google account from the current user.
    /// </summary>
    public async Task UnlinkGoogleAccount()
    {
        var principal = _httpContextAccessor.HttpContext?.User;
        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? "";
        
        var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == Guid.Parse(userId));

        if (user is null) return;
        
        user.GoogleId = null;
        
        _dbContext.Users.Update(user);
        await _dbContext.SaveChangesAsync();
    }

    /// <summary>
    ///     Retrieves the Google OAuth2 callback URL from the configuration.
    /// </summary>
    /// <returns>The Google OAuth2 callback URL.</returns>
    public string GetGoogleCallbackUrl()
    {
        var credentials = GetGoogleCredentials();
        
        if (credentials.RedirectUrl is not null) return credentials.RedirectUrl;
        
        var request = _httpContextAccessor.HttpContext?.Request;
        
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        
        var baseUrl = $"{request.Scheme}://{request.Host}";
        
        return $"{baseUrl}/auth/google/callback";
    }

    /// <summary>
    ///     Generates a new OAuth2 state token and stores it in a cookie.
    /// </summary>
    /// <returns>The hashed OAuth2 state token.</returns>
    public string GenerateOauthStateToken()
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        var hashedToken = Convert.ToBase64String(hash);
        
        _httpContextAccessor.HttpContext?.Response.Cookies.Append("oauth_state", token, new CookieOptions
        {
            HttpOnly = true,
            SameSite = _sameSiteMode,
            Secure = true,
            Expires = DateTime.UtcNow.AddMinutes(5)
        });

        return hashedToken;
    }

    /// <summary>
    ///     Validates the OAuth2 state token against the stored cookie.
    /// </summary>
    /// <param name="state">The OAuth2 state token to validate.</param>
    /// <returns>True if the token is valid, false otherwise.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with an HTTP status code of HttpStatusCode.Unauthorized (401) if the state token is invalid.
    /// </exception>
    public bool ValidateOauthStateToken(string state)
    {
        var cookie = _httpContextAccessor.HttpContext?.Request.Cookies["oauth_state"];

        if (string.IsNullOrEmpty(cookie))
        {
            throw new HttpResponseException(HttpStatusCode.Unauthorized);
        }
        
        _httpContextAccessor.HttpContext?.Response.Cookies.Delete("oauth_state", new CookieOptions() { SameSite = _sameSiteMode, Secure = true });
        
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(cookie));
        var token = Convert.ToBase64String(hash);
        
        return state == token;
    }
    
    /// <summary>
    ///     Verifies the email of a user using the provided confirmation token.
    /// </summary>
    /// <param name="token">The confirmation token used to verify the email.</param>
    /// <returns>True if the email was successfully verified, false otherwise.</returns>
    public async Task<bool> VerifyEmail(string token)
    {
        var confirmationToken = await _dbContext.UserTokens
            .OfType<AccountConfirmationToken>()
            .Where(t => t.Token == token)
            .Include(t => t.User)
            .FirstOrDefaultAsync();
        
        if (confirmationToken is null || confirmationToken.ExpiresAt < DateTime.UtcNow)
        {
            return false;
        }

        var user = confirmationToken.User;

        user.EmailConfirmed = true;

        _dbContext.Users.Update(user);
        _dbContext.UserTokens.Remove(confirmationToken);
        await _dbContext.SaveChangesAsync();
        
        return true;
    }

    /// <summary>
    ///     Revokes a user session using the provided session ID and password.
    /// </summary>
    /// <param name="userId">The ID of the user whose session is being revoked.</param>
    /// <param name="sessionId">The ID of the session being revoked.</param>
    /// <param name="password">The user's password used to verify the session.</param>
    /// <returns>True if the session was successfully revoked, false otherwise.</returns>
    public async Task<bool> RevokeSession(Guid userId, Guid sessionId, string password)
    {
        var session = await _dbContext.UserSessions
            .Include(s => s.User)
            .FirstOrDefaultAsync(s => s.Id == sessionId && s.User.Id == userId);
        
        if (session is null || session.ExpiresAt < DateTime.UtcNow)
        {
            return true;
        }
        
        var user = session.User;

        if (!VerifyPassword(user, password))
        {
            return false;
        }
        
        
        session.IsRevoked = true;
        
        _dbContext.UserSessions.Update(session);
        await _dbContext.SaveChangesAsync();
        
        return true;
    }

    /// <summary>
    ///     Logs out the current user by removing the session from the database and deleting the refresh token cookie.
    /// </summary>
    public async Task Logout()
    {
        var principal = _httpContextAccessor.HttpContext?.User;
        var sessionId = principal.FindFirstValue(ClaimTypes.PrimarySid) ?? "";
        
        var session = await _dbContext.UserSessions
            .Include(s => s.User)
            .FirstOrDefaultAsync(s => s.Id == Guid.Parse(sessionId));
        
        if (session is not null)
        {
            _dbContext.UserSessions.Remove(session);
            await _dbContext.SaveChangesAsync();
        }
        
        _httpContextAccessor.HttpContext?.Response.Cookies.Delete("refresh_token", new CookieOptions() { SameSite = _sameSiteMode, Secure = true });
    }

    /// <summary>
    ///     Generates a confirmation token for the user with the provided email.
    /// </summary>
    /// <param name="email">The email of the user to generate the confirmation token for.</param>
    /// <returns>A <see cref="AccountConfirmationToken"/> object containing the confirmation token on success, null otherwise.</returns>
    public async Task<AccountConfirmationToken?> GenerateConfirmationToken(string email)
    {
        var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == email);

        if (user is null || user.EmailConfirmed) return null;
        
        return await GenerateConfirmationToken(user);
    }

    /// <summary>
    ///     Generates a password reset token for the user with the provided email.
    /// </summary>
    /// <param name="email">The email of the user to generate the password reset token for.</param>
    /// <returns>A <see cref="PasswordResetToken"/> object containing the password reset token on success, null otherwise.</returns>
    public async Task<PasswordResetToken?> GeneratePasswordResetToken(string email)
    {
        var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == email);

        if (user is null) return null;
        
        using var rng = RandomNumberGenerator.Create();

        for (var retry = 0; retry < _maxRetries; retry++)
        {
            var tokenBytes = new byte[256];
            rng.GetBytes(tokenBytes);
            var token = Convert.ToBase64String(tokenBytes);

            var passwordResetToken = new PasswordResetToken
            {
                UserId = user.Id,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                Token = token
            };

            try
            {
                _dbContext.UserTokens.Add(passwordResetToken);
                await _dbContext.SaveChangesAsync();

                return passwordResetToken;
            }
            catch (DbUpdateException e)
            {
                if(e.InnerException is Npgsql.PostgresException { SqlState: "23505" }) // Postgres unique constraint violation
                {
                    _logger.LogWarning("Token collision detected (retry {Retry}). Generating a new token.", retry + 1);
                }
                else
                {
                    throw;
                }
            }
        }

        _logger.LogError("Failed to generate password reset token after {MaxRetries} attempts", _maxRetries);
        throw new HttpResponseException(HttpStatusCode.InternalServerError, "Failed to generate password reset token");
    }

    /// <summary>
    ///     Resets the password of a user using the provided data.
    /// </summary>
    /// <param name="data">A <see cref="ResetPasswordDto"/> object containing the user's ID, token, and new password.</param>
    /// <exception cref="HttpResponseException">
    ///     Thrown with an HTTP status code of HttpStatusCode.Unauthorized (401) if the token is invalid or expired.
    /// </exception>
    public async Task ResetPassword(ResetPasswordDto data)
    {
        var tokenEntry = await _dbContext.UserTokens
            .OfType<PasswordResetToken>()
            .Include(t => t.User)
            .ThenInclude(user => user.UserSessions)
            .FirstOrDefaultAsync(t => t.Token == data.Token);
        
        if (tokenEntry is null || tokenEntry.ExpiresAt < DateTime.UtcNow)
        {
            throw new HttpResponseException(HttpStatusCode.Unauthorized);
        }
        
        var user = tokenEntry.User;
        
        var salt = new byte[128 / 8];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        var userSessions = user.UserSessions;
        
        _dbContext.UserSessions.RemoveRange(userSessions);
        
        user.PasswordHash = HashPassword(data.Password, salt);
        user.PasswordSalt = salt;
        
        _dbContext.Users.Update(user);
        
        _dbContext.UserTokens.Remove(tokenEntry);
        await _dbContext.SaveChangesAsync();
    }
    
    /// <summary>
    ///     Updates the password of the user.
    /// </summary>
    /// <param name="user">The user whose password is being updated.</param>
    /// <param name="data">A <see cref="UpdatePasswordDto"/> object containing the user's current password and new password.</param>
    /// <returns>The updated user.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with different HTTP status codes depending on the validation failure:
    ///     <list type="bullet">
    ///         <item>
    ///             HttpStatusCode.Unauthorized (401): If the current password is invalid.
    ///         </item>
    ///         <item>
    ///             HttpStatusCode.BadRequest (400): If the new password does not meet the validation criteria.
    ///         </item>
    ///     </list>
    /// </exception>
    public async Task<User> UpdatePassword(User user, UpdatePasswordDto data)
    {
        if (!VerifyPassword(user, data.CurrentPassword))
        {
            throw new HttpResponseException(HttpStatusCode.Unauthorized, "Current password is invalid");
        }
        
        var errors = ValidatePassword(data.NewPassword);
        if (errors.Count > 0)
        {
            throw new HttpResponseException(HttpStatusCode.BadRequest, "New password is invalid", new Dictionary<string, object> {{"password", errors}});
        }
        
        var salt = new byte[128 / 8];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        
        user.PasswordHash = HashPassword(data.NewPassword, salt);
        user.PasswordSalt = salt;
        
        _dbContext.Users.Update(user);
        await _dbContext.SaveChangesAsync();
        
        return user;
    }
    
    /// <summary>
    /// Generates a confirmation token for the specified user.
    /// </summary>
    /// <param name="user">The user for whom the confirmation token is generated.</param>
    /// <returns>A <see cref="AccountConfirmationToken"/> object containing the generated token.</returns>
    /// <remarks>
    /// This method generates a unique confirmation token for the user and stores it in the database.
    /// The token is valid for 1 hour from the time of generation.
    /// </remarks>
    private async Task<AccountConfirmationToken> GenerateConfirmationToken(User user)
    {
        using var rng = RandomNumberGenerator.Create();

        for (var retry = 0; retry < _maxRetries; retry++)
        {
            var tokenBytes = new byte[256];
            rng.GetBytes(tokenBytes);
            var token = Convert.ToBase64String(tokenBytes);

            var userConfirmationToken = new AccountConfirmationToken
            {
                UserId = user.Id,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                Token = token
            };

            try
            {
                _dbContext.UserTokens.Add(userConfirmationToken);
                await _dbContext.SaveChangesAsync();

                return userConfirmationToken;
            }
            catch (DbUpdateException e)
            {
                if(e.InnerException is Npgsql.PostgresException { SqlState: "23505" }) // Postgres unique constraint violation
                {
                    _logger.LogWarning("Token collision detected (retry {Retry}). Generating a new token.", retry + 1);
                }
                else
                {
                    throw;
                }
            }
        }

        _logger.LogError("Failed to generate confirmation token after {MaxRetries} attempts", _maxRetries);
        throw new HttpResponseException(HttpStatusCode.InternalServerError, "Failed to generate confirmation token");
    }

    /// <summary>
    ///     Generates an account completion token for the specified email and Google ID.
    /// </summary>
    /// <param name="email">
    ///     The email of the user for whom the account completion token is generated.
    /// </param>
    /// <param name="googleId">
    ///     The Google ID of the user for whom the account completion token is generated.
    /// </param>
    /// <returns>A <see cref="AccountCompletionToken"/> object containing the generated token.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with an HTTP status code of HttpStatusCode.InternalServerError (500) if the token cannot be generated.
    /// </exception>
    private async Task<AccountCompletionToken> GenerateCompletionToken(string email, string googleId)
    {
        using var rng = RandomNumberGenerator.Create();

        for (var retry = 0; retry < _maxRetries; retry++)
        {
            var tokenBytes = new byte[256 / 8];
            rng.GetBytes(tokenBytes);
            var token = Convert.ToBase64String(tokenBytes);

            var accountCompletionToken = new AccountCompletionToken
            {
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                Token = token,
                Email = email,
                GoogleId = googleId
            };

            try
            {
                _dbContext.UserTokens.Add(accountCompletionToken);
                await _dbContext.SaveChangesAsync();

                return accountCompletionToken;
            }
            catch (DbUpdateException e)
            {
                if(e.InnerException is Npgsql.PostgresException { SqlState: "23505" }) // Postgres unique constraint violation
                {
                    _logger.LogWarning("Token collision detected (retry {Retry}). Generating a new token.", retry + 1);
                }
                else
                {
                    throw;
                }
            }
        }

        _logger.LogError("Failed to generate account completion token after {MaxRetries} attempts", _maxRetries);
        throw new HttpResponseException(HttpStatusCode.InternalServerError, "Failed to generate account completion token");
    }
    
    /// <summary>
    ///     Links the Google account to the user.
    /// </summary>
    /// <param name="googleId">The Google ID of the user to link the account to.</param>
    /// <param name="user">The user to link the Google account to.</param>
    /// <returns>The updated user.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with different HTTP status codes depending on the validation failure:
    ///     <list type="bullet">
    ///         <item>
    ///             HttpStatusCode.BadRequest (400): If the Google account is already linked to another user.
    ///         </item>
    ///         <item>
    ///             HttpStatusCode.Conflict (409): If the user already has a linked Google account.
    ///         </item>
    ///     </list>
    /// </exception>
    private async Task<User> LinkGoogleAccount(string googleId, User user)
    {
        if (user.GoogleId is not null)
        {
            throw new HttpResponseException(HttpStatusCode.BadRequest, "User already has a linked Google account");
        }

        try
        {
            user.GoogleId = googleId;

            _dbContext.Users.Update(user);
            await _dbContext.SaveChangesAsync();
        }
        catch (DbUpdateException e)
        {
            if (e.InnerException is Npgsql.PostgresException { SqlState: "23505" }) // Postgres unique constraint violation
            {
                throw new HttpResponseException(HttpStatusCode.Conflict, "The google account is already linked to another user");
            }

            throw;
        }

        return user;
    }

    private async Task<GoogleUserData?> GetGoogleAccountData(string code, string redirectUri)
    {
        var credentials = GetGoogleCredentials();
        
        // Send http request to exchange code for token
        var url = new UriBuilder("https://oauth2.googleapis.com/token")
            .ToString();
        
        var body = new
        {
            client_id = credentials.ClientId,
            client_secret = credentials.ClientSecret,
            code = code,
            grant_type = "authorization_code",
            redirect_uri = redirectUri
        }.ToJson();
        
        var response = await _httpClient.PostAsync(url, new StringContent(body, Encoding.UTF8, "application/json"));
        var data = await response.Content.ReadFromJsonAsync<GoogleTokenData>();
        
        if (data is null || string.IsNullOrEmpty(data.AccessToken))
        {
            return null;
        }
        
        var userData = await _httpClient.GetFromJsonAsync<GoogleUserData>($"https://www.googleapis.com/oauth2/v2/userinfo?access_token={data.AccessToken}");

        return userData;
    }
    
    /// <summary>
    ///     Generates an account linking token for the specified user and Google ID.
    /// </summary>
    /// <param name="user">The user for whom the account linking token is generated.</param>
    /// <param name="googleId">The Google ID to link to the user.</param>
    /// <returns>A <see cref="AccountLinkingToken"/> object containing the generated token.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with an HTTP status code of HttpStatusCode.InternalServerError (500) if the token cannot be generated.
    /// </exception>
    private async Task<AccountLinkingToken> GenerateLinkingToken(User user, string googleId)
    {
        using var rng = RandomNumberGenerator.Create();

        for (var retry = 0; retry < _maxRetries; retry++)
        {
            var tokenBytes = new byte[256 / 8];
            rng.GetBytes(tokenBytes);
            var token = Convert.ToBase64String(tokenBytes);

            var accountLinkingToken = new AccountLinkingToken()
            {
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                Token = token,
                GoogleId = googleId,
                User = user
            };

            try
            {
                _dbContext.UserTokens.Add(accountLinkingToken);
                await _dbContext.SaveChangesAsync();

                return accountLinkingToken;
            }
            catch (DbUpdateException e)
            {
                if(e.InnerException is Npgsql.PostgresException { SqlState: "23505" }) // Postgres unique constraint violation
                {
                    _logger.LogWarning("Token collision detected (retry {Retry}). Generating a new token.", retry + 1);
                }
                else
                {
                    throw;
                }
            }
        }

        _logger.LogError("Failed to generate account linking token after {MaxRetries} attempts", _maxRetries);
        throw new HttpResponseException(HttpStatusCode.InternalServerError, "Failed to generate account linking token");
    }

    /// <summary>
    ///     Generates a refresh token for the specified user.
    /// </summary>
    /// <param name="user">The user for whom the refresh token is generated.</param>
    /// <param name="extendedLifespan">A boolean indicating whether the refresh token should have an extended lifespan.</param>
    /// <param name="storeInCookie">A boolean indicating whether the refresh token should be stored in a cookie.</param>
    /// <returns>A <see cref="RefreshTokenData"/> object containing the generated refresh token.</returns>
    private async Task<RefreshTokenData> GenerateRefreshToken(User user, bool extendedLifespan = false, bool storeInCookie = true)
    {
        string token;
        byte[] encryptedToken;
        do
        {
           token = Guid.NewGuid().ToString();
        
           encryptedToken = EncryptRefreshToken(token);
        } while (_dbContext.UserSessions.Any(s => s.RefreshToken == encryptedToken));

        var session = new UserSession
        {
            User = user,
            RefreshToken = encryptedToken,
            ExpiresAt = DateTime.UtcNow.AddDays(extendedLifespan ? 90 : 7),
            HasLongLivedRefreshToken = extendedLifespan
        };
        
        await _dbContext.UserSessions.AddAsync(session);
        await _dbContext.SaveChangesAsync();

        if (storeInCookie)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = _sameSiteMode,
                Expires = session.ExpiresAt,
                Path = "/api/auth/refresh"
            };

            _httpContextAccessor.HttpContext?.Response.Cookies.Append("refresh_token", token, cookieOptions);
        }
        
        return new RefreshTokenData
        {
            Session = session,
            Token = token
        };
    }

    /// <summary>
    ///     Validates the refresh token and generates a new one if it is valid.
    /// </summary>
    /// <param name="token">The refresh token to validate.</param>
    /// <returns>A <see cref="RefreshTokenData"/> object containing the user session data if the token is valid, null otherwise.</returns>
    private async Task<RefreshTokenData?> ValidateRefreshToken(string token)
    {
        var encryptedToken = EncryptRefreshToken(token);

        var session = await _dbContext.UserSessions
            .Include(s => s.User)
            .FirstOrDefaultAsync(s => s.RefreshToken == encryptedToken);
        
        if (session is null || session.ExpiresAt < DateTime.UtcNow)
        {
            return null;
        }
        
        string newRefreshToken;
        byte[] newEncryptedToken;
        do
        {
            newRefreshToken = Guid.NewGuid().ToString();
        
            newEncryptedToken = EncryptRefreshToken(newRefreshToken);
        } while (_dbContext.UserSessions.FirstOrDefault(s => s.RefreshToken == newEncryptedToken) is not null);
        
        session.ExpiresAt = DateTime.UtcNow.AddDays(session.HasLongLivedRefreshToken ? 90 : 7);
        session.RefreshToken = newEncryptedToken;
        await _dbContext.SaveChangesAsync();

        return new RefreshTokenData()
        {
            Session = session,
            Token = newRefreshToken
        };
    }
    
    private byte[] EncryptRefreshToken(string token)
    {
        var encryptionKey = _config.GetSection("Authentication:RefreshSecret").Value;
        
        if (encryptionKey is null)
        {
            throw new ArgumentNullException(nameof(encryptionKey));
        }
        
        byte[] encryptedToken;
        using (var aes = Aes.Create())
        {
            var key = Convert.FromBase64String(encryptionKey);
            aes.Key = key;
            aes.IV = new byte[16];

            var encryptor = aes.CreateEncryptor();
            var tokenBytes = Encoding.UTF8.GetBytes(token);
            encryptedToken = encryptor.TransformFinalBlock(tokenBytes, 0, tokenBytes.Length);
        }
        
        return encryptedToken;
    }

    /// <summary>
    ///     Hashes the provided password using the provided salt.
    /// </summary>
    /// <param name="password">The password to hash.</param>
    /// <param name="salt">The salt to use for hashing.</param>
    /// <returns>The hashed password.</returns>
    private byte[] HashPassword(string password, byte[] salt)
    {
        return KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 10000,
            numBytesRequested: 256 / 8
        );
    }

    /// <summary>
    ///     Generates a JWT token using the provided data.
    /// </summary>
    /// <param name="data">A <see cref="JwtData"/> object containing data to include in the JWT token.</param>
    /// <returns>The generated JWT token.</returns>
    /// <exception cref="ArgumentNullException">Thrown if the JWT secret is not found in the configuration.</exception>
    private string GenerateJwt(JwtData data)
    {
        var claims = new List<Claim>()
        {
            new Claim(ClaimTypes.NameIdentifier, data.Id.ToString()),
            new Claim(ClaimTypes.Name, data.Username),
            new Claim(ClaimTypes.Email, data.Email),
            new Claim(ClaimTypes.PrimarySid, data.SessionId.ToString())
        };

        var secret = _config.GetSection("Authentication:JwtSecret").Value;

        if (secret is null)
        {
            throw new ArgumentNullException(nameof(secret));
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddHours(3),
            signingCredentials: creds
        );

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        return tokenString;
    }
    
    /// <summary>
    ///     Validates the provided password against the validation criteria.
    /// </summary>
    /// <param name="password">The password to validate.</param>
    /// <returns>A list of error messages if the password is invalid, an empty list otherwise.</returns>
    private List<string> ValidatePassword(string password)
    {
        var errors = new List<string>();
        
        if (password.Length < 8)
        {
            errors.Add("Password must be at least 8 characters long");
        }
        
        if (!password.Any(char.IsUpper))
        {
            errors.Add("Password must contain at least one uppercase letter");
        }
        
        if (!password.Any(char.IsLower))
        {
            errors.Add("Password must contain at least one lowercase letter");
        }
        
        if (!password.Any(char.IsDigit))
        {
            errors.Add("Password must contain at least one digit");
        }
        
        return errors;
    }
    
    /// <summary>
    ///     Verifies the provided password against the user's password hash.
    /// </summary>
    /// <param name="user">The user to verify the password against.</param>
    /// <param name="password">The password to verify.</param>
    /// <returns>True if the password is correct, false otherwise.</returns>
    private bool VerifyPassword(User user, string password)
    {
        var enteredPasswordHash = HashPassword(password, user.PasswordSalt);

        return enteredPasswordHash.SequenceEqual(user.PasswordHash);
    }
}