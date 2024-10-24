namespace SnowrunnerMergerApi.Models.Auth.Dtos;

/// <summary>
/// DTO for resetting a user's password.
/// </summary>
public record ResetPasswordDto
{
    /// <summary>
    /// Gets the user ID.
    /// </summary>
    public Guid UserId { get; init; }

    /// <summary>
    /// Gets the token for password reset.
    /// </summary>
    public string Token { get; init; }

    /// <summary>
    /// Gets the new password.
    /// </summary>
    public string Password { get; init; }
};