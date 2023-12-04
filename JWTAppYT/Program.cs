using JWTAppYT;
using JWTAppYT.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
ConfigurationManager configuration = builder.Configuration;

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.Configure<AppSettings>(
    builder.Configuration.GetSection("ApplicationSettings"));

builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddCookie(x =>
{
    x.Cookie.Name = "token";

}).AddJwtBearer(x =>
{
    x.RequireHttpsMetadata = false;
    x.SaveToken = true;
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["ApplicationSettings:Secret"])),
        ValidateIssuer = false,
        ValidateAudience = false
    };
    x.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            context.Token = context.Request.Cookies["X-Access-Token"];
            return Task.CompletedTask;
        }
    };

});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin", "HR").RequireClaim("id", "Alif"));
    options.AddPolicy("ExclusiveContentPolicy",
        policy => policy.RequireAssertion(context => context.User.HasClaim(claim => claim.Type == "id" && claim.Value == "Alif") ||
        context.User.IsInRole("SuperAdmin")));

    options.AddPolicy("IsOldEnoughWithRole", policy => policy.AddRequirements(new IsOldEnoughWithRoleRequirement(21)));
});

builder.Services.AddSingleton<IAuthorizationHandler, IsOldEnoughWithRoleHandler>();
builder.Services.AddHttpClient();

builder.Services.AddCors(opt =>
{
    opt.AddPolicy(name: "AllowAll", builder =>
    {
        builder.WithOrigins("http://localhost:4200", "https://localhost:4200")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("AllowAll");

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
