using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace cms.Domain.Entities;

public class User
{
    [Key]
    public required Guid Id { get; init; }
    public required string Email { get; set; }
    public required string Username { get; set; }
    public required string Password { get; set; }
    public required bool Has2Fa { get; set; }
    public required bool IsAdmin { get; set; }

    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}