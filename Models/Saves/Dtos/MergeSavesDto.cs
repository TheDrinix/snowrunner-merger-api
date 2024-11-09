using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Saves.Dtos;

public record MergeSavesDto
{
    [Required]
    public IFormFile Save { get; init; }
    [Range(0, 3)]
    [Required]
    public int SaveNumber { get; init; }
    [Range(0, 3)]
    [Required]
    public int OutputSaveNumber { get; init; }
};