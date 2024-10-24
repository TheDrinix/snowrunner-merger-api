namespace SnowrunnerMergerApi.Models.Auth.Dtos;

/// <summary>
/// DTO representing the response data for a login request.
/// </summary>
public record LoginResponseDto
{
    /// <summary>
    /// Gets the access token.
    /// </summary>
    public string AccessToken { get; init; }

    /// <summary>
    /// Gets the access token expiration time in seconds.
    /// </summary>
    public int ExpiresIn { get; init; }

    /// <summary>
    /// Gets the user information.
    /// </summary>
    public User User { get; init; }
};