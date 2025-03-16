namespace SnowrunnerMergerApi.Models.Auth;

public record MailConfig
{
    public string Host { get; set; }
    public int Port { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
    public string Address { get; set; }
};