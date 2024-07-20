using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Auth.Dtos;

public record VerifyEmailDto
{
    [Required]
    public Guid UserId { get; set; }
    [Required]
    public string Token { get; set; }
};