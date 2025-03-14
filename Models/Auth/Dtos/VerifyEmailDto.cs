using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Auth.Dtos;

/// <summary>
/// DTO for verifying email.
/// </summary>
public record VerifyEmailDto
{
    /// <summary>
    /// Gets the verification token.
    /// </summary>
    [Required]
    public string Token { get; init; }
};