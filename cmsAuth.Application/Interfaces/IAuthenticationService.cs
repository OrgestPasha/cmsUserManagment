using cms.Domain.Entities;
using cmsAuth.Application.DTO;

namespace cmsAuth.Application.Interfaces;


public interface IAuthenticationService
{
    public object? Login(string email, string password);
    public Task<bool> Register(RegisterUser user);
    public string RefreshToken(string token);
    public void Logout(string token);
}