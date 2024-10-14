using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Auth.Dtos;

public record UpdateUsernameDto()
{
    [Required]
    [Length(3,20)]
    public string Username { get; init; }
};