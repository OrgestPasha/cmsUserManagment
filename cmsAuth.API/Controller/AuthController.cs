using cmsAuth.Application.DTO;
using cmsAuth.Application.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace cmsAuth.Controller;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    public AuthController(IAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
    }

    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterUser user)
    {
        var result = _authenticationService.Register(user);
        return Ok(result);
    }

    [HttpGet("login")]
    public IActionResult Login([FromQuery] string e, [FromQuery] string p)
    {
        try
        {
            var user = _authenticationService.Login(e, p);
            return Ok(user);
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }
}