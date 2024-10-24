using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Auth.Dtos;

/// <summary>
/// DTO for user registration.
/// </summary>
public record RegisterDto
{
    /// <summary>
    /// Gets the username.
    /// </summary>
    [Required]
    [Length(3, 20)]
    public string Username { get; init; }

    /// <summary>
    /// Gets the email address.
    /// </summary>
    [Required]
    [EmailAddress]
    public string Email { get; init; }

    /// <summary>
    /// Gets the password.
    /// </summary>
    [Required]
    public string Password { get; init; }
};