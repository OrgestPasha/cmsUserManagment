namespace cmsUserManagment.Application.Common.ErrorCodes;

public class AuthErrorCodes : Exception
{
    public static readonly AuthErrorCodes tokenNotFound = new(1, "Token not found");
    public static readonly AuthErrorCodes notCorrectCode = new(2, "Code is not correct");
    public static readonly AuthErrorCodes failedToLogOut = new(3, "Failed to logout");
    public static readonly AuthErrorCodes badToken = new(4, "Bad token");
    public int code;
    public string message;

    public AuthErrorCodes(int code, string message)
    {
        this.code = code;
        this.message = message;
    }
}
