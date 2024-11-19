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
    /// <returns>A <see cref="UserToken"/> object containing the confirmation token for the user.</returns>
    Task<UserToken> Register(RegisterDto data);
    /// <summary>
    /// Attempts to log in a user with the provided credentials.
    /// </summary>
    /// <param name="data">A <see cref="LoginDto"/> object containing the user's email and password.</param>
    /// <returns>A <see cref="LoginResponseDto"/> object containing the access token, expiration time, and user information on success.</returns>
    Task<LoginResponseDto> Login(LoginDto data);
    /// <summary>
    ///  Attempts to refresh the access token using the provided refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token used to generate a new access token.</param>
    /// <param name="isCookieToken">A boolean indicating whether the refresh token is stored in a cookie.</param>
    /// <param name="extendedLifespan">A boolean indicating whether the new refresh token should have an extended lifespan.</param>
    /// <returns>A <see cref="RefreshResponseDto"/> object containing the new access token, expiration time, and user information on success.</returns>
    Task<RefreshResponseDto> RefreshToken(string refreshToken, bool isCookieToken = true);
    /// <summary>
    ///     Retrieves a long-lived refresh token for the user.
    /// </summary>
    /// <param name="userId">The ID of the user to generate the refresh token for.</param>
    /// <returns>A <see cref="RefreshTokenDto"/> object containing the long-lived refresh token and expiration time on success.</returns>
    Task<RefreshTokenDto> GetLongLivedRefreshToken(Guid userId);
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
    bool ValidateOauthStateToken(string state);
    /// <summary>
    ///     Attempts to sign in a user using the provided Google OAuth2 code.
    ///     If the user does not exist, a new user is created.
    /// </summary>
    /// <param name="code">The Google OAuth2 code used to exchange for an access token.</param>
    /// <param name="redirectUri">The redirect URI used to exchange the code.</param>
    /// <returns>A <see cref="LoginResponseDto"/> object containing the access token, expiration time, and user information on success.</returns>
    Task<LoginResponseDto> GoogleSignIn(string code, string redirectUri);

    /// <summary>
    ///     Retrieves the Google OAuth2 callback URL from the configuration.
    /// </summary>
    /// <returns>The Google OAuth2 callback URL.</returns>
    public string GetGoogleCallbackUrl();
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
    /// <returns>A <see cref="UserToken"/> object containing the confirmation token on success, null otherwise.</returns>
    Task<UserToken?> GenerateConfirmationToken(string email);
    /// <summary>
    ///     Generates a password reset token for the user with the provided email.
    /// </summary>
    /// <param name="email">The email of the user to generate the password reset token for.</param>
    /// <returns>A <see cref="UserToken"/> object containing the password reset token on success, null otherwise.</returns>
    Task<UserToken?> GeneratePasswordResetToken(string email);
    /// <summary>
    ///     Resets the password of a user using the provided data.
    /// </summary>
    /// <param name="data">A <see cref="ResetPasswordDto"/> object containing the user's ID, token, and new password.</param>
    Task ResetPassword(ResetPasswordDto data);

    /// <summary>
    ///     Updates the password of the user.
    /// </summary>
    /// <param name="user">The user whose password is being updated.</param>
    /// <param name="data">A <see cref="UpdatePasswordDto"/> object containing the user's current password and new password.</param>
    /// <returns>The updated user.</returns>
    Task<User> UpdatePassword(User user, UpdatePasswordDto data);
}

