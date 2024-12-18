using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Quartz;
using SnowrunnerMergerApi.Data;
using SnowrunnerMergerApi.Exceptions;
using SnowrunnerMergerApi.Extensions;
using SnowrunnerMergerApi.Jobs;
using SnowrunnerMergerApi.Models;
using SnowrunnerMergerApi.Services;
using SnowrunnerMergerApi.Services.Interfaces;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers(opt =>
{
    opt.Filters.Add<HttpResponseExceptionFilter>();
});
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(opt =>
{
    opt.SwaggerDoc("v1", new OpenApiInfo { Title = "Snowrunner Merger Api", Version = "v1" });
    opt.EnableAnnotations();
});

builder.Services.AddDbContext<AppDbContext>(opt =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

    if (connectionString is null)
    {
        throw new ArgumentNullException(nameof(connectionString));
    }
    
    opt.UseNpgsql(connectionString);
});

builder.Services.AddCors(opt =>
{
    opt.AddPolicy("dev", policy =>
    {
        policy.WithOrigins("https://localhost:44303", "http://localhost:5173", "https://localhost:5051");
        policy.AllowAnyHeader();
        policy.AllowAnyMethod();
        policy.AllowCredentials();
    });
    
    opt.AddPolicy("prod", policy =>
    {
        policy.WithOrigins("https://snowrunner.drinix.xyz");
        policy.AllowAnyHeader();
        policy.AllowAnyMethod();
        policy.AllowCredentials();
    });
});

builder.Services.SetupAuthentication(builder.Configuration);

builder.Services.AddAuthorization();

builder.Services.AddHttpContextAccessor();

builder.Services.AddAutoMapper(typeof(MapperProfile));
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IGroupsService, GroupsService>();
builder.Services.AddScoped<ISavesService, SavesService>();
builder.Services.AddTransient<IEmailSender, EmailSender>();

builder.Services.AddQuartz(q =>
{
    var tokensJobKey = new JobKey("PurgeExpiredTokensJob", "Purge");
    q.AddJob<PurgeExpiredTokensJob>(tokensJobKey);
    q.AddTrigger(t => t
        .WithIdentity("Purge expired tokens trigger")
        .ForJob(tokensJobKey)
        .WithCronSchedule("0 0 3 ? * SUN"));
    
    var sessionsJobKey = new JobKey("RevokeExpiredSessionsJob", "Purge");
    q.AddJob<PurgeExpiredSessionsJob>(sessionsJobKey);
    q.AddTrigger(t => t
        .WithIdentity("Purge expired sessions trigger")
        .ForJob(sessionsJobKey)
        .WithCronSchedule("0 0 3 ? * SUN"));
});

builder.Services.AddQuartzHostedService(opt => opt.WaitForJobsToComplete = true);

var app = builder.Build();
AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseCors("dev");
}
else
{
    app.UseCors("prod");
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();