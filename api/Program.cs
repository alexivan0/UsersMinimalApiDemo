
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// ca sa putem primi rolurile (admin/user) sub forma de string
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

// EF cu SQLite
builder.Services.AddDbContext<AppDbContext>(opts =>
{
    // pentru deploy pe diferite medii am pune conn string in env variables
    var cs = builder.Configuration.GetConnectionString("Default")
             ?? throw new InvalidOperationException("Missing ConnectionStrings:Default.");
    opts.UseSqlite(cs);
});

// CORS pentru angular
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.WithOrigins("http://localhost:4200")
     .AllowAnyHeader()
     .AllowAnyMethod()
));

// auth cu jwt
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));
var jwtOptions = builder.Configuration.GetSection("Jwt").Get<JwtOptions>()
                 ?? throw new InvalidOperationException("Missing Jwt section.");

if (string.IsNullOrWhiteSpace(jwtOptions.Key))
    throw new InvalidOperationException("Missing Jwt:Key.");
if (string.IsNullOrWhiteSpace(jwtOptions.Issuer))
    throw new InvalidOperationException("Missing Jwt:Issuer.");
if (string.IsNullOrWhiteSpace(jwtOptions.Audience))
    throw new InvalidOperationException("Missing Jwt:Audience.");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Key))
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// scoped (per-request) mai simplu de dezvoltat pe viitor fara concurency issues (fata de singleton)
builder.Services.AddScoped<IPasswordHasher, Rfc2898PasswordHasher>();

var app = builder.Build();

// seed pentru demo
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    // EnsureCreated mai usor pentru demo, in mod normal am folosi migratii pentru versionare
    db.Database.EnsureCreated();
    if (!db.Users.Any())
    {
        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
        var admin = new User
        {
            Id = Guid.NewGuid(),
            FullName = "Admin One",
            Email = "admin@example.com",
            Role = Role.Admin,
            Status = Status.Active,
            CreatedAt = DateTime.UtcNow,
            CreatedBy = "seed",
        };
        admin.PasswordHash = hasher.Hash("Admin123!");
        var user = new User
        {
            Id = Guid.NewGuid(),
            FullName = "User One",
            Email = "user@example.com",
            Role = Role.User,
            Status = Status.Active,
            CreatedAt = DateTime.UtcNow,
            CreatedBy = "seed",
        };
        user.PasswordHash = hasher.Hash("User123!");
        db.Users.AddRange(admin, user);
        db.SaveChanges();
    }
}

app.UseSwagger();
app.UseSwaggerUI();

app.UseCors();

// valideaza jwt din header
app.UseAuthentication();
// aplica authorize pe roluri
app.UseAuthorization();

app.MapGet("/", () => Results.Redirect("/swagger"));

app.MapPost("/api/auth/login", async ([FromBody] LoginDto dto, AppDbContext db, IPasswordHasher hasher, IOptions<JwtOptions> jwtOpt) =>
{
    if (string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Password))
        return Results.BadRequest(new { error = "Email and password required." });

    var user = await db.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
    if (user is null) return Results.Unauthorized();

    if (!hasher.Verify(user.PasswordHash, dto.Password))
        return Results.Unauthorized();

    var token = CreateJwt(user, jwtOpt.Value);
    var dtoOut = UserDto.FromEntity(user);
    return Results.Ok(new { token, user = dtoOut });
});

app.MapGet("/api/me", [Authorize] async (ClaimsPrincipal claims, AppDbContext db) =>
{
    var email = claims.FindFirstValue(ClaimTypes.Email);
    if (email is null) return Results.Unauthorized();

    //AsNotracking pentru ca stim ca functia e read only, mai rapid la citire
    var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Email == email);
    return user is null ? Results.NotFound() : Results.Ok(UserDto.FromEntity(user));
});

app.MapGet("/api/users", [Authorize(Roles = "Admin")] async (AppDbContext db) =>
{
    var list = await db.Users.AsNoTracking().OrderBy(u => u.FullName).ToListAsync();
    return list.Select(UserDto.FromEntity);
});

app.MapGet("/api/users/{id:guid}", [Authorize(Roles = "Admin")] async (Guid id, AppDbContext db) =>
{
    var user = await db.Users.FindAsync(id);
    return user is null ? Results.NotFound() : Results.Ok(UserDto.FromEntity(user));
});

app.MapPost("/api/users", [Authorize(Roles = "Admin")] async ([FromBody] UserCreateDto dto, AppDbContext db, ClaimsPrincipal claims, IPasswordHasher hasher) =>
{
    if (await db.Users.AnyAsync(u => u.Email == dto.Email))
        return Results.Conflict(new { error = "Email already exists." });

    // "system" ca fallback pentru audit (CreatedBy)
    var creator = claims.FindFirstValue(ClaimTypes.Email) ?? "system";
    var user = new User
    {
        Id = Guid.NewGuid(),
        FullName = dto.FullName,
        Email = dto.Email,
        Role = dto.Role,
        Status = dto.Status,
        CreatedAt = DateTime.UtcNow,
        CreatedBy = creator,
        PasswordHash = hasher.Hash(dto.Password)
    };
    var validationErrors = DtoValidator.ValidateFullName(dto.FullName);
    validationErrors.AddRange(DtoValidator.ValidateEmail(dto.Email));
    validationErrors.AddRange(DtoValidator.ValidatePassword(dto.Password, required: true));
    if (validationErrors.Count != 0)
        return Results.BadRequest(new { errors = validationErrors });

    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Created($"/api/users/{user.Id}", UserDto.FromEntity(user));
});

app.MapPut("/api/users/{id:guid}", [Authorize(Roles = "Admin")] async (Guid id, [FromBody] UserUpdateDto dto, AppDbContext db, ClaimsPrincipal claims, IPasswordHasher hasher) =>
{
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();

    var errors = DtoValidator.ValidateFullName(dto.FullName);
    errors.AddRange(DtoValidator.ValidateEmail(dto.Email));
    errors.AddRange(DtoValidator.ValidatePassword(dto.Password, required: false));
    if (errors.Count != 0)
        return Results.BadRequest(new { errors });

    if (!string.Equals(user.Email, dto.Email, StringComparison.OrdinalIgnoreCase) &&
        await db.Users.AnyAsync(u => u.Email == dto.Email))
        return Results.Conflict(new { error = "Email already exists." });

    user.FullName = dto.FullName;
    user.Email = dto.Email;
    user.Role = dto.Role;
    user.Status = dto.Status;
    if (!string.IsNullOrWhiteSpace(dto.Password))
        user.PasswordHash = hasher.Hash(dto.Password);

    user.ModifiedAt = DateTime.UtcNow;
    user.ModifiedBy = claims.FindFirstValue(ClaimTypes.Email) ?? "system";

    await db.SaveChangesAsync();
    return Results.Ok(UserDto.FromEntity(user));
});

app.MapDelete("/api/users/{id:guid}", [Authorize(Roles = "Admin")] async (Guid id, AppDbContext db) =>
{
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();
    db.Users.Remove(user);
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.Run();

static string CreateJwt(User user, JwtOptions opts)
{
    var handler = new JwtSecurityTokenHandler();
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(opts.Key));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()!),
        new Claim(ClaimTypes.Email, user.Email),
        new Claim(ClaimTypes.Name, user.FullName),
        new Claim(ClaimTypes.Role, user.Role.ToString())
    };

    var token = new JwtSecurityToken(
        issuer: opts.Issuer,
        audience: opts.Audience,
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(opts.ExpiresMinutes),
        signingCredentials: creds
    );

    return handler.WriteToken(token);
}

// data cu EF
public class AppDbContext : DbContext
{
    public DbSet<User> Users => Set<User>();

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(e =>
        {
            // index pe email pentru fast reads
            e.HasIndex(u => u.Email).IsUnique();
            e.Property(u => u.Role).HasConversion<string>();
            e.Property(u => u.Status).HasConversion<string>();
        });
    }
}

public enum Role { Admin, User }
public enum Status { Active, Inactive }

public class User
{
    public Guid Id { get; set; }
    public string FullName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public Role Role { get; set; } = Role.User;
    public Status Status { get; set; } = Status.Active;
    public DateTime CreatedAt { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public DateTime? ModifiedAt { get; set; }
    public string? ModifiedBy { get; set; }

    public string PasswordHash { get; set; } = string.Empty;
}

// dtos si validari
public record LoginDto(string Email, string Password);

public record UserDto(Guid Id, string FullName, string Email, string Role, string Status, DateTime CreatedAt, string CreatedBy, DateTime? ModifiedAt, string? ModifiedBy)
{
    public static UserDto FromEntity(User u) => new UserDto(u.Id, u.FullName, u.Email, u.Role.ToString(), u.Status.ToString(), u.CreatedAt, u.CreatedBy, u.ModifiedAt, u.ModifiedBy);
}

public record UserCreateDto
{
    public string FullName { get; init; } = string.Empty;
    public string Email { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public Role Role { get; init; } = Role.User;
    public Status Status { get; init; } = Status.Active;
}

public record UserUpdateDto
{
    public string FullName { get; init; } = string.Empty;
    public string Email { get; init; } = string.Empty;
    public string? Password { get; init; }
    public Role Role { get; init; } = Role.User;
    public Status Status { get; init; } = Status.Active;
}

public static class DtoValidator
{
    public static List<string> ValidateEmail(string email)
    {
        var errors = new List<string>();
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            if (addr.Address != email) errors.Add("Invalid email format.");
        }
        catch { errors.Add("Invalid email format."); }
        return errors;
    }

    public static List<string> ValidateFullName(string fullName)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(fullName) || fullName.Length < 2 || fullName.Length > 100)
            errors.Add("FullName must be between 2 and 100 characters.");
        return errors;
    }

    public static List<string> ValidatePassword(string? password, bool required, int min = 6, int max = 100)
    {
        var errors = new List<string>();

        if (required && string.IsNullOrWhiteSpace(password))
        {
            errors.Add("Password is required.");
            return errors;
        }

        if (password is null) return errors;

        if (string.IsNullOrWhiteSpace(password))
        {
            errors.Add("Password cannot be empty.");
            return errors;
        }

        if (password.Length < min || password.Length > max)
            errors.Add($"Password must be between {min} and {max} characters.");

        return errors;
    }
}

// auth utils
public class JwtOptions
{
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public required string Key { get; set; }
    public int ExpiresMinutes { get; set; } = 120;
}

public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string hash, string password);
}

// sub forma: {iterations}.{saltBase64}.{hashBase64}
public class Rfc2898PasswordHasher : IPasswordHasher
{
    private const int Iterations = 100_000;
    private const int SaltSize = 16;
    private const int KeySize = 32;

    public string Hash(string password)
    {
        using var rng = RandomNumberGenerator.Create();
        var salt = new byte[SaltSize];
        rng.GetBytes(salt);
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
        var key = pbkdf2.GetBytes(KeySize);
        return $"{Iterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(key)}";
    }

    public bool Verify(string hash, string password)
    {
        try
        {
            var parts = hash.Split('.');
            var iterations = int.Parse(parts[0]);
            var salt = Convert.FromBase64String(parts[1]);
            var key = Convert.FromBase64String(parts[2]);
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            var key2 = pbkdf2.GetBytes(key.Length);
            // mai safe, comparatia se face la final ca sa eviti hinturi date de early return
            return CryptographicOperations.FixedTimeEquals(key2, key);
        }
        catch { return false; }
    }
}
