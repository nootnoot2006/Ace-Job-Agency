using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Ace_Job_Agency.Services
{
 public class StubEmailSender : IEmailSender
 {
 private readonly ILogger<StubEmailSender> _logger;
 public StubEmailSender(ILogger<StubEmailSender> logger)
 {
 _logger = logger;
 }
 public Task SendEmailAsync(string to, string subject, string body)
 {
 _logger.LogInformation("Stub email sent to {to} with subject {subject}. Email body omitted from logs for security.", to, subject);
 return Task.CompletedTask;
 }
 }
}
