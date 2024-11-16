using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SnowrunnerMergerApi.Data;

namespace SnowrunnerMergerApi.Extensions;

public static class AuthenticationExtension
{
    public static IServiceCollection SetupAuthentication(this IServiceCollection services, IConfiguration config)
    {
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(opt =>
            {
                var jwtSecret = config.GetSection("Authentication:JwtSecret").Value;
        
                if (jwtSecret is null)
                {
                    throw new ArgumentNullException(nameof(jwtSecret));
                }
        
                opt.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8
                        .GetBytes(jwtSecret)),
                    ValidateIssuer = false,
                    ValidateAudience = false
                };

                opt.IncludeErrorDetails = true;

                opt.Events = new JwtBearerEvents()
                {
                    OnMessageReceived = ctx =>
                    {
                        if (ctx.Request.Headers.ContainsKey("Authorization"))
                        {
                            var token = ctx.Request.Headers["Authorization"].ToString().Split(" ");

                            if (token is ["Bearer", _])
                            {
                                ctx.Token = token[1];
                            }
                        }
                        
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = ctx =>
                    {
                        var userId =
                            Guid.Parse(ctx.Principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value ??
                                       "");
                        var sessionId =
                            Guid.Parse(ctx.Principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.PrimarySid)?.Value ?? "");

                        if (userId == Guid.Empty || sessionId == Guid.Empty)
                        {
                            ctx.Fail("Invalid token");
                        }

                        var dbContext = ctx.HttpContext.RequestServices.GetRequiredService<AppDbContext>();
                        var session = dbContext.UserSessions.FirstOrDefault(s => s.Id == sessionId && s.UserId == userId);

                        if (session is null || session.IsRevoked || session.ExpiresAt < DateTime.UtcNow)
                        {
                            ctx.Fail("Invalid token");
                        }

                        return Task.CompletedTask;
                    }
                };
            });
        
        return services;
    }
}