using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Saves.Dtos;

public record MergeSavesDto
{
    [Required]
    public IFormFile Save { get; set; }
    [Range(1, 4)]
    [Required]
    public int SaveNumber { get; set; }
    [Range(1, 4)]
    [Required]
    public int OutputSaveNumber { get; set; }
};