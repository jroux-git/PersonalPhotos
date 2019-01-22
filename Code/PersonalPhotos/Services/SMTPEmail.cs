using Microsoft.Extensions.Options;
using PersonalPhotos.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace PersonalPhotos.Services
{
    public class SmtpEmail : IEmail
    {
        private readonly EmailOptions _emailOptions;

        public SmtpEmail(IOptions<EmailOptions> emailOptions)
        {
            _emailOptions = emailOptions.Value;
        }

        public async Task Send(string emailAddress, string body)
        {
            var client = new SmtpClient();
            client.Host = _emailOptions.Host;
            //client.Port = 25;
            client.Credentials = new NetworkCredential(_emailOptions.Username, _emailOptions.Password);
            
            var message = new MailMessage("jproux264@hotmail.com", emailAddress);
            message.Body = body;
            message.IsBodyHtml = true;

            await client.SendMailAsync(message);
        }
    }
}
