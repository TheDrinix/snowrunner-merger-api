using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Auth.Dtos;

public record RequestResetPasswordDto()
{
    [EmailAddress]
    public string Email { get; set; }
};