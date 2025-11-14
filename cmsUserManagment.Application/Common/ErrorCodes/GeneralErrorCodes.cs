namespace cmsUserManagment.Application.Common.ErrorCodes;

public class GeneralErrorCodes : Exception
{
    public static readonly GeneralErrorCodes NotFound
        = new(1, "The requested resource was not found.");

    public static readonly GeneralErrorCodes UserAlreadyExists
        = new(2, "A user with the provided information already exists.");

    public static readonly GeneralErrorCodes InvalidInput
        = new(3, "The provided input is invalid or missing required fields.");

    public static readonly GeneralErrorCodes OperationFailed
        = new(4, "The requested operation failed due to an internal error.");

    public static readonly GeneralErrorCodes DatabaseError
        = new(5, "A database-related error occurred.");

    public static readonly GeneralErrorCodes Conflict
        = new(6, "A conflict occurred with an existing resource.");

    public static readonly GeneralErrorCodes ServiceUnavailable
        = new(7, "The service is currently unavailable. Please try again later.");

    public static readonly GeneralErrorCodes PermissionDenied
        = new(8, "You do not have permission to perform this operation.");

    public static readonly GeneralErrorCodes ValidationError
        = new(9, "One or more validation errors occurred.");

    public static readonly GeneralErrorCodes Unknown
        = new(10, "An unknown error has occurred.");

    public static readonly GeneralErrorCodes PasswordTooWeak
        = new(11,
            "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.");

    public static readonly GeneralErrorCodes UsernameTooShort
        = new(12, "Username must be at least 5 characters long.");

    public static readonly GeneralErrorCodes InvalidEmailFormat
        = new(13, "Email format is invalid.");

    public GeneralErrorCodes(int code, string message) : base(message)
    {
        Code = code;
    }

    public int Code { get; }
}
