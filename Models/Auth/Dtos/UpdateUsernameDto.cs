using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Auth.Dtos;

/// <summary>
/// DTO for updating the username.
/// </summary>
public record UpdateUsernameDto()
{
    /// <summary>
    /// The new username.
    /// </summary>
    [Required]
    [Length(3,20)]
    public string Username { get; init; }
};