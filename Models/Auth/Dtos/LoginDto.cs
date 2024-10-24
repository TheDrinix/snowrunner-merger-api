namespace SnowrunnerMergerApi.Models.Auth.Dtos;

/// <summary>
/// DTO for user login.
/// </summary>
public record LoginDto
{
    /// <summary>
    /// Gets the email of the user.
    /// </summary>
    public string Email { get; init; }

    /// <summary>
    /// Gets the password of the user.
    /// </summary>
    public string Password { get; init; }
};