using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace cms.Domain.Entities;

public class RefreshToken
{
    [Key] public Guid Id { get; init; }

    public DateTime Expires { get; init; } = DateTime.UtcNow.AddDays(90);

    [ForeignKey(nameof(User))] public required Guid UserId { get; init; }

    public User User { get; init; }
}
