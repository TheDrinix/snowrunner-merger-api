namespace SnowrunnerMergerApi.Models.Auth.Dtos;

public record ResetPasswordDto
{
    public Guid UserId { get; set; }
    public string Token { get; set; }
    public string Password { get; set; }
};