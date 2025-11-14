using cmsUserManagment.Application.DTO;
using cmsUserManagment.Application.Interfaces;
using cmsUserManagment.Infrastructure.Security;

using Google.Authenticator;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace cmsUserManagment.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class AuthController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    private readonly HeadersManager _headersManager;
    private readonly IJwtTokenProvider _jwtTokenProvider;

    public AuthController(IAuthenticationService authenticationService, IJwtTokenProvider jwtTokenProvider,
        HeadersManager headersManager)
    {
        _authenticationService = authenticationService;
        _jwtTokenProvider = jwtTokenProvider;
        _headersManager = headersManager;
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterUser newUser)
    {
        bool result = await _authenticationService.Register(newUser);
        return Ok(result);
    }


    [HttpGet("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login(string email, string password)
    {
        object? tokens = await _authenticationService.Login(email, password);
        return Ok(tokens);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] Guid refreshToken)
    {
        string jwt = _headersManager.GetJwtFromHeader(Request.Headers);

        await _authenticationService.Logout(jwt, refreshToken);
        return Ok();
    }

    [HttpGet("refresh-token")]
    public async Task<IActionResult> RefreshToken(Guid refreshToken)
    {
        string token =
            await _authenticationService.RefreshToken(refreshToken, _headersManager.GetJwtFromHeader(Request.Headers));
        return Ok(token);
    }

    [HttpPost("generate-two-factor-auth-code")]
    public async Task<SetupCode> GenerateTwoFactorAuthSetupCode()
    {
        SetupCode setupCode =
            await _authenticationService.GenerateAuthToken(_headersManager.GetJwtFromHeader(Request.Headers));
        return setupCode;
    }

    [HttpPost("two-factor-auth-confirm")]
    public async Task<bool> TwoFactorAuthenticationConfirm([FromBody] string code)
    {
        bool result =
            await _authenticationService.TwoFactorAuthenticationConfirm(
                _headersManager.GetJwtFromHeader(Request.Headers), code);
        return result;
    }

    [HttpDelete("disable-two-factor-auth")]
    public async Task<bool> DisableTwoFactorAuth()
    {
        bool result =
            await _authenticationService.DisableTwoFactorAuth(_headersManager.GetJwtFromHeader(Request.Headers));
        return result;
    }


    [HttpPost("login-with-two-factor-auth")]
    [AllowAnonymous]
    public async Task<IActionResult?> TwoFactorAuthenticationLogin(string loginId, string code)
    {
        LoginCredentials token = await _authenticationService.TwoFactorAuthenticationLogin(Guid.Parse(loginId), code);
        return Ok(token);
    }
}
