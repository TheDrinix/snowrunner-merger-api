using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Models.Auth.Dtos;
using SnowrunnerMergerApi.Models.Auth.Google;

namespace SnowrunnerMergerApi.Services.Interfaces;

public interface IAuthService
{
    /// <summary>
    /// Registers a new user using the provided data.
    /// </summary>
    /// <param name="data">A <see cref="RegisterDto"/> object containing the user's registration details.</param>
    /// <returns>A <see cref="UserConfirmationToken"/> object containing the confirmation token for the user.</returns>
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
    Task<UserConfirmationToken> Register(RegisterDto data);
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
    Task<LoginResponseDto> Login(LoginDto data);
    /// <summary>
    ///  Attempts to refresh the access token using the provided refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token used to generate a new access token.</param>
    /// <returns>A <see cref="LoginResponseDto"/> object containing the new access token, expiration time, and user information on success.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with an HTTP status code of HttpStatusCode.Unauthorized (401) if the refresh token is invalid.
    /// </exception>
    Task<LoginResponseDto> RefreshToken(string token);
    /// <summary>
    ///     Retrieves the Google OAuth2 credentials from the configuration.
    /// </summary>
    /// <returns>A <see cref="GoogleCredentials"/> object containing the Google OAuth2 client ID and secret.</returns>
    GoogleCredentials GetGoogleCredentials();
    /// <summary>
    ///     Generates a new OAuth2 state token and stores it in a cookie.
    /// </summary>
    /// <returns>The hashed OAuth2 state token.</returns>
    string GenerateOauthStateToken();
    /// <summary>
    ///     Validates the OAuth2 state token against the stored cookie.
    /// </summary>
    /// <param name="state">The OAuth2 state token to validate.</param>
    /// <returns>True if the token is valid, false otherwise.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with an HTTP status code of HttpStatusCode.Unauthorized (401) if the state token is invalid.
    /// </exception>
    bool ValidateOauthStateToken(string state);
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
    Task<LoginResponseDto> GoogleSignIn(string code, string redirectUri);
    /// <summary>
    ///     Verifies the email of a user using the provided confirmation token.
    /// </summary>
    /// <param name="userId">The ID of the user whose email is being verified.</param>
    /// <param name="token">The confirmation token used to verify the email.</param>
    /// <returns>True if the email was successfully verified, false otherwise.</returns>
    Task<bool> VerifyEmail(Guid userId, string token);
    /// <summary>
    ///     Logs out the current user by removing the session from the database and deleting the refresh token cookie.
    /// </summary>
    Task Logout();
    /// <summary>
    ///     Generates a confirmation token for the user with the provided email.
    /// </summary>
    /// <param name="email">The email of the user to generate the confirmation token for.</param>
    /// <returns>A <see cref="UserConfirmationToken"/> object containing the confirmation token on success, null otherwise.</returns>
    Task<UserConfirmationToken?> GenerateConfirmationToken(string email);
    /// <summary>
    ///     Generates a password reset token for the user with the provided email.
    /// </summary>
    /// <param name="email">The email of the user to generate the password reset token for.</param>
    /// <returns>A <see cref="PasswordResetToken"/> object containing the password reset token on success, null otherwise.</returns>
    Task<PasswordResetToken?> GeneratePasswordResetToken(string email);
    /// <summary>
    ///     Resets the password of a user using the provided data.
    /// </summary>
    /// <param name="data">A <see cref="ResetPasswordDto"/> object containing the user's ID, token, and new password.</param>
    /// <exception cref="HttpResponseException">
    ///     Thrown with an HTTP status code of HttpStatusCode.Unauthorized (401) if the token is invalid or expired.
    /// </exception>
    Task ResetPassword(ResetPasswordDto data);
}

