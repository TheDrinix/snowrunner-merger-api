using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Saves.Dtos;

public record UploadSaveDto
{
    [MinLength(3)]
    [MaxLength(100)]
    public string Description { get; init; }
    [Required]
    // [FileExtensions(Extensions = "zip")]
    public IFormFile Save { get; init; }
    [Range(0, 3)]
    [Required]
    public int SaveNumber { get; init; }
};