namespace Ace_Job_Agency.Services
{
 public interface IEmailSender
 {
 Task SendEmailAsync(string to, string subject, string body);
 }
}
