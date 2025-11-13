namespace cmsUserManagment.Application.DTO;

public class TwoFactorCodeInput
{
    public Guid loginId { get; set; }
    public string code { get; set; }
}
