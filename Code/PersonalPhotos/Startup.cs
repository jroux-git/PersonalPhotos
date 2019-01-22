using System.Reflection;
using Core.Interfaces;
using Core.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PersonalPhotos.Filters;
using PersonalPhotos.Interfaces;
using PersonalPhotos.Services;

namespace PersonalPhotos
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var connectionString = Configuration.GetConnectionString("Default");
            var currentAssemblyName = Assembly.GetExecutingAssembly().GetName().Name;

            services.AddMvc();
            services.AddSession();
            services.AddScoped<ILogins, SqlServerLogins>();
            services.AddSingleton<IKeyGenerator, DefaultKeyGenerator>();
            services.AddScoped<IPhotoMetaData, SqlPhotoMetaData>();
            services.AddScoped<IFileStorage, LocalFileStorage>();
            services.AddScoped<LoginAttribute>();
            services.Configure<EmailOptions>(Configuration.GetSection("Email"));

            services.AddDbContext<IdentityDbContext>(options => {
                options.UseSqlServer(connectionString, obj => {
                    obj.MigrationsAssembly(currentAssemblyName);
                });
            });
        
            services.AddIdentity<IdentityUser, IdentityRole>(options =>
            {
                options.Password = new PasswordOptions
                {
                    RequireDigit = false,
                    RequiredLength = 4,
                    RequiredUniqueChars = 4,
                    RequireUppercase = true
                };
                options.User = new UserOptions
                {
                    RequireUniqueEmail = true
                };
                options.SignIn = new SignInOptions
                {
                    RequireConfirmedEmail = false,
                    RequireConfirmedPhoneNumber = false
                };
                options.Lockout = new LockoutOptions
                {
                    AllowedForNewUsers = false,
                    DefaultLockoutTimeSpan = new System.TimeSpan(0,15,0),
                    MaxFailedAccessAttempts = 3
                };
            })
            .AddEntityFrameworkStores<IdentityDbContext>()
            .AddDefaultTokenProviders();

            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Logins/Index";
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("EditorOver18Policy", policy =>
                {
                    policy.RequireClaim("Over18Claim");//.RequireRole("Editor");
                });
            });

            services.AddSingleton<IEmail, SmtpEmail>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseBrowserLink();
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseAuthentication();
            app.UseStaticFiles();
            app.UseSession();
            app.UseAuthentication();
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    "default",
                    "{controller=Photos}/{action=Display}");
            });
        }
    }
}