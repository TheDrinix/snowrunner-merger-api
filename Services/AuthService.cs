using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SnowrunnerMergerApi.Data;
using SnowrunnerMergerApi.Exceptions;
using SnowrunnerMergerApi.Models;
using SnowrunnerMergerApi.Models.Dtos;

namespace SnowrunnerMergerApi.Services;

public interface IAuthService
{
    Task<User> Register(RegisterDto data);
    Task<LoginResponseDto> Login(LoginDto data);
    Task<LoginResponseDto> RefreshToken(string token);
    public JwtData GetUserSessionData();
}

public class AuthService : IAuthService
{
    private readonly ILogger<AuthService> _logger;
    private readonly AppDbContext _dbContext;
    private readonly IConfiguration _config;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuthService(
        ILogger<AuthService> logger,
        AppDbContext dbContext,
        IConfiguration config,
        IHttpContextAccessor httpContextAccessor
    )
    {
        _logger = logger;
        _dbContext = dbContext;
        _config = config;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<User> Register(RegisterDto data)
    {
        var passwordErrors = ValidatePassword(data.Password);
        if (passwordErrors.Count > 0)
        {
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Invalid password", errors: passwordErrors);
        }
        
        var normalizedEmail = data.Email.ToUpper();
        var normalizedUsername = data.Username.ToUpper();

        var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail);
        if (user is not null)
        {
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Email already in use");
        }

        var salt = new byte[128 / 8];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        
        user = new User()
        {
            Email = data.Email,
            NormalizedEmail = normalizedEmail,
            Username = data.Username,
            NormalizedUsername = normalizedUsername,
            PasswordHash = HashPassword(data.Password, salt),
            PasswordSalt = salt,
            CreatedAt = DateTime.Now,
            EmailConfirmed = false
        };
        
        // TODO: Send confirmation email
        
        await _dbContext.Users.AddAsync(user);
        await _dbContext.SaveChangesAsync();
        
        return user;
    }
    
    public async Task<LoginResponseDto> Login(LoginDto data)
    {
        var user = await _dbContext.Users
            .FirstOrDefaultAsync(u => u.NormalizedEmail == data.Email.ToUpper());
        
        if (user is null)
        {
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Invalid email or password");
        }
        
        if (!user.EmailConfirmed)
        {
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Email not confirmed");
        }
        
        var passwordHash = HashPassword(data.Password, user.PasswordSalt);
        
        if (!user.PasswordHash.SequenceEqual(passwordHash))
        {
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Invalid email or password");
        }

        var token = GenerateJwt(new JwtData() { Id = user.Id, Username = user.Username, Email = user.Email });

        var sessionData = await GenerateRefreshToken(user);
        
        return new LoginResponseDto
        {
            AccessToken = token,
            ExpiresIn = 60 * 60 * 24,
            RefreshToken = sessionData.RefreshToken,
            RefreshTokenExpiresAt = sessionData.ExpiresAt,
            User = user
        };
    }
    
    public async Task<LoginResponseDto> RefreshToken(string refreshToken)
    {
        var sessionData = await ValidateRefreshToken(refreshToken);
        
        if (sessionData is null)
        {
            throw new HttpResponseException(HttpStatusCode.Unauthorized);
        }
        
        var token = GenerateJwt(new JwtData() { Id = sessionData.User.Id, Username = sessionData.User.Username, Email = sessionData.User.Email });
        
        
        return new LoginResponseDto
        {
            AccessToken = token,
            ExpiresIn = 60 * 60 * 24,
            RefreshToken = sessionData.RefreshToken,
            RefreshTokenExpiresAt = sessionData.ExpiresAt,
            User = sessionData.User
        };
    }

    public JwtData GetUserSessionData()
    {
        var principal = _httpContextAccessor.HttpContext?.User;
        
        var id = principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        var username = principal?.FindFirstValue(ClaimTypes.Name);
        var email = principal?.FindFirstValue(ClaimTypes.Email);
        
        if (id is null || username is null || email is null)
        {
            _logger.LogError("User session data not found");
            throw new HttpResponseException(HttpStatusCode.Unauthorized);
        }
        
        return new JwtData
        {
            Id = Guid.Parse(id),
            Username = username,
            Email = email
        };
    }

    private async Task<RefreshTokenData> GenerateRefreshToken(User user)
    {
        string token;
        byte[] encryptedToken;
        do
        {
           token = Guid.NewGuid().ToString();
        
           encryptedToken = EncryptRefreshToken(token);
        } while (_dbContext.UserSessions.FirstOrDefault(s => s.RefreshToken == encryptedToken) is not null);

        var session = new UserSession
        {
            User = user,
            RefreshToken = encryptedToken,
            ExpiresAt = DateTime.Now.AddDays(7)
        };
        
        await _dbContext.UserSessions.AddAsync(session);
        await _dbContext.SaveChangesAsync();
        
        return new RefreshTokenData()
        {
            ExpiresAt = session.ExpiresAt,
            RefreshToken = token,
            User = user
        };
    }

    private async Task<RefreshTokenData?> ValidateRefreshToken(string token)
    {
        var encryptedToken = EncryptRefreshToken(token);

        var session = await _dbContext.UserSessions
            .Include(s => s.User)
            .FirstOrDefaultAsync(s => s.RefreshToken == encryptedToken);
        
        if (session is null || session.ExpiresAt < DateTime.Now)
        {
            return null;
        }
        
        string newRefreshToken;
        byte[] newEncryptedToken;
        do
        {
            newRefreshToken = Guid.NewGuid().ToString();
        
            newEncryptedToken = EncryptRefreshToken(newRefreshToken);
        } while (_dbContext.UserSessions.FirstOrDefault(s => s.RefreshToken == newEncryptedToken) is not null);
        
        session.ExpiresAt = DateTime.Now.AddDays(7);
        session.RefreshToken = newEncryptedToken;
        await _dbContext.SaveChangesAsync();
        
        return new RefreshTokenData()
        {
            ExpiresAt = session.ExpiresAt,
            RefreshToken = newRefreshToken,
            User = session.User
        };
    }
    
    private byte[] EncryptRefreshToken(string token)
    {
        var encryptionKey = _config.GetSection("AppSettings:RefreshSecret").Value;
        
        if (encryptionKey is null)
        {
            throw new ArgumentNullException(nameof(encryptionKey));
        }
        
        byte[] encryptedToken;
        using (var aes = Aes.Create())
        {
            var key = Convert.FromBase64String(encryptionKey);
            aes.Key = key;
            aes.IV = new byte[16];

            var encryptor = aes.CreateEncryptor();
            var tokenBytes = Encoding.UTF8.GetBytes(token);
            encryptedToken = encryptor.TransformFinalBlock(tokenBytes, 0, tokenBytes.Length);
        }
        
        return encryptedToken;
    }

    private byte[] HashPassword(string password, byte[] salt)
    {
        return KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 10000,
            numBytesRequested: 256 / 8
        );
    }

    private string GenerateJwt(JwtData data)
    {
        var claims = new List<Claim>()
        {
            new Claim(ClaimTypes.NameIdentifier, data.Id.ToString()),
            new Claim(ClaimTypes.Name, data.Username),
            new Claim(ClaimTypes.Email, data.Email)
        };

        var secret = _config.GetSection("AppSettings:JwtSecret").Value;

        if (secret is null)
        {
            throw new ArgumentNullException(nameof(secret));
        }

        var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: creds
        );

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        return tokenString;
    }
    
    private List<string> ValidatePassword(string password)
    {
        var errors = new List<string>();
        
        if (password.Length < 8)
        {
            errors.Add("Password must be at least 8 characters long");
        }
        
        if (!password.Any(char.IsUpper))
        {
            errors.Add("Password must contain at least one uppercase letter");
        }
        
        if (!password.Any(char.IsLower))
        {
            errors.Add("Password must contain at least one lowercase letter");
        }
        
        if (!password.Any(char.IsDigit))
        {
            errors.Add("Password must contain at least one digit");
        }
        
        return errors;
    }
}