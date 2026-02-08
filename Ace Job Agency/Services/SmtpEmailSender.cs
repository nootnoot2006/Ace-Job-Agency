using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Ace_Job_Agency.Services
{
    /// <summary>
    /// Sends emails via SMTP (Gmail, Outlook, or any SMTP server).
    /// Configure in appsettings.json under "Smtp" section.
    /// </summary>
    public class SmtpEmailSender : IEmailSender
    {
 private readonly IConfiguration _configuration;
        private readonly ILogger<SmtpEmailSender> _logger;

        public SmtpEmailSender(IConfiguration configuration, ILogger<SmtpEmailSender> logger)
 {
            _configuration = configuration;
            _logger = logger;
 }

   public async Task SendEmailAsync(string to, string subject, string body)
  {
  try
            {
   var smtpHost = _configuration["Smtp:Host"];
      var smtpPort = int.Parse(_configuration["Smtp:Port"] ?? "587");
   var smtpUser = _configuration["Smtp:Username"];
                var smtpPass = _configuration["Smtp:Password"];
           var fromEmail = _configuration["Smtp:FromEmail"];
        var fromName = _configuration["Smtp:FromName"] ?? "Ace Job Agency";

       if (string.IsNullOrEmpty(smtpHost) || string.IsNullOrEmpty(smtpUser) || string.IsNullOrEmpty(smtpPass))
    {
       _logger.LogWarning("SMTP not configured. Email not sent to {To}: {Subject}", to, subject);
   return;
                }

           using var client = new SmtpClient(smtpHost, smtpPort)
    {
         Credentials = new NetworkCredential(smtpUser, smtpPass),
          EnableSsl = true
  };

  var mailMessage = new MailMessage
    {
      From = new MailAddress(fromEmail ?? smtpUser, fromName),
      Subject = subject,
              Body = body,
        IsBodyHtml = true
        };
       mailMessage.To.Add(to);

 await client.SendMailAsync(mailMessage);
  _logger.LogInformation("Email sent to {To}: {Subject}", to, subject);
            }
  catch (Exception ex)
            {
     _logger.LogError(ex, "Failed to send email to {To}: {Subject}", to, subject);
     throw;
        }
        }
    }
}
