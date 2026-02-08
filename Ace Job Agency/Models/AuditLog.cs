using System.ComponentModel.DataAnnotations;

namespace Ace_Job_Agency.Models
{
 public class AuditLog
 {
 public int Id { get; set; }
 [Required]
 public string EventType { get; set; }
 public string? UserId { get; set; }
 public string? IpAddress { get; set; }
 public string? UserAgent { get; set; }
 public DateTime Timestamp { get; set; }
 public string? Details { get; set; }
 }
}
