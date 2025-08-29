using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using dk.nita.saml20.Configuration;
using dk.nita.saml20.config;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();

// Bind configuration POCOs
builder.Services.Configure<SAML20FederationConfigOptions>(builder.Configuration.GetSection("SAML20FederationConfig"));
builder.Services.Configure<FederationConfigOptions>(builder.Configuration.GetSection("FederationConfig"));

// Register config services
builder.Services.AddSingleton<SAML20FederationConfigService>();
builder.Services.AddSingleton<FederationConfigService>();

var app = builder.Build();

app.MapControllers();

app.Run();
