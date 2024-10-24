using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Auth.Dtos;

/// <summary>
/// DTO for resending confirmation emails.
/// </summary>
public record ResendConfirmationDto
{
    /// <summary>
    /// The email address to resend the confirmation to.
    /// </summary>
    [EmailAddress]
    public string Email { get; init; }
};