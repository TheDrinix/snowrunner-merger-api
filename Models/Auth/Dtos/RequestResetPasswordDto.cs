using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Auth.Dtos;

/// <summary>
/// DTO for requesting a password reset.
/// </summary>
public record RequestResetPasswordDto()
{
    /// <summary>
    /// The email address of the user requesting the password reset.
    /// </summary>
    [EmailAddress]
    public string Email { get; init; }
};