using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Auth.Dtos;

public record CreateGroupDto
{
    [Microsoft.Build.Framework.Required]
    [MinLength(3)]
    [MaxLength(64)]
    public string Name { get; set; }
};