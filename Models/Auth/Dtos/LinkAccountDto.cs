namespace SnowrunnerMergerApi.Models.Auth.Dtos;

public record LinkAccountDto
{
    public string LinkingToken { get; init; }
};