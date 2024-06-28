using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Dtos;

public record RegisterDto
{
    [Required]
    [Length(3, 20)]
    public string Username { get; set; }
    [Required]
    [EmailAddress]
    public string Email { get; set; }
    [Required]
    public string Password { get; set; }
};