using System.Net;
using System.Net.Mail;
using SnowrunnerMergerApi.Models.Auth;

namespace SnowrunnerMergerApi.Services;

public interface IEmailSender
{
    Task SendEmailAsync(string email, string subject, string message);
}

public class EmailSender : IEmailSender
{
    private readonly ILogger<EmailSender> _logger;
    private readonly IConfiguration _config;
    public EmailSender(ILogger<EmailSender> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;
    }
    
    public async Task SendEmailAsync(string email, string subject, string message)
    {
        var mailConfigSlice = _config.GetSection("SMTP");
        if (mailConfigSlice is null)
        {
            throw new ArgumentNullException(nameof(mailConfigSlice));
        }
        
        var mailConfig = mailConfigSlice.Get<MailConfig>();
        if (mailConfig is null)
        {
            throw new ArgumentNullException(nameof(mailConfig));
        }

        using var client = new SmtpClient();

        client.Port = mailConfig.Port;
        client.Host = mailConfig.Host;
        client.EnableSsl = true;
        client.DeliveryMethod = SmtpDeliveryMethod.Network;
        client.UseDefaultCredentials = false;
        client.Credentials = new NetworkCredential(mailConfig.Username, mailConfig.Password);
        var mail = new MailMessage("noreply@drinix.xyz", email)
        {
            Subject = subject,
            Body = message,
            IsBodyHtml = true
        };
            
        mail.From = new MailAddress("noreply@drinix.xyz", "Snowrunner Merger");
            
        await client.SendMailAsync(mail);
    }
}