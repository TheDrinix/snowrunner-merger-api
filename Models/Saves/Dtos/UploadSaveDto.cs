using System.ComponentModel.DataAnnotations;

namespace SnowrunnerMergerApi.Models.Saves.Dtos;

public record UploadSaveDto
{
    [MinLength(3)]
    [MaxLength(100)]
    public string Description { get; set; }
    [Required]
    // [FileExtensions(Extensions = "zip")]
    public IFormFile Save { get; set; }
    [Range(1, 4)]
    [Required]
    public int SaveNumber { get; set; }
};