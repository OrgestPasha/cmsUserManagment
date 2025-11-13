namespace cmsUserManagment.Application.Common.ErrorCodes;

public class GeneralErrorCodes(int code, string message) : Exception
{
    public static readonly GeneralErrorCodes notFound = new(1, "User not found");
    public static readonly GeneralErrorCodes exists = new(2, "User already exists");
    public int code = code;
    public string message = message;
}
