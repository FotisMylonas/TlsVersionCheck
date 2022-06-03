using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using System;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TlsVersionCheck
{
    public class TlsVersionChecker
    {
        private ILogger<TlsVersionChecker> Log { get; }
        public TlsVersionChecker(ILogger<TlsVersionChecker> log)
        {
            Log = log;
        }
        public void TryAllProtocols(string server)
        {
            var protocols = Enum.GetValues(typeof(SslProtocols)).Cast<SslProtocols>();
            foreach (var p in protocols)
            {
                try
                {
                    ConnectUsingProtocol(server, p);
                }
                catch (Exception ex)
                {
                    Log.LogError(ex.Message);
                }
            }
        }

        public void ConnectUsingProtocol(string server, SslProtocols protocol)
        {
            Log.LogInformation($"connect to {server} using {protocol}");
            TcpClient client = new TcpClient(server, 443);
            SslStream sslStream = new SslStream(
                client.GetStream(), false,
                new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            try
            {
                sslStream.AuthenticateAsClient(server, null, protocol, false);
                StringBuilder sb = new StringBuilder();
                sb.AppendLine($"SslProtocol (1):{protocol}");
                sb.AppendLine($"SslProtocol (2):{sslStream.SslProtocol}");
                sb.AppendLine($"CipherAlgorithm:{sslStream.CipherAlgorithm}");
                sb.AppendLine($"CipherStrength:{sslStream.CipherStrength}");
                sb.AppendLine($"HashAlgorithm:{sslStream.HashAlgorithm}");
                sb.AppendLine($"HashStrength:{sslStream.HashStrength}");
                sb.AppendLine($"KeyExchangeAlgorithm:{sslStream.KeyExchangeAlgorithm}");
                sb.AppendLine($"KeyExchangeStrength:{sslStream.KeyExchangeStrength}");
                sb.AppendLine($"NegotiatedApplicationProtocol:{sslStream.NegotiatedApplicationProtocol}");
                sb.AppendLine($"NegotiatedCipherSuite:{sslStream.NegotiatedCipherSuite}");
                Log.LogInformation(sb.ToString());

            }
            catch (Exception e)
            {
                Log.LogError("authentication failure: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Log.LogError("Inner exception: {0}", e.InnerException.Message);
                }
            }
            finally
            {
                client.Close();
            }
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

    }
    internal class Program
    {
        static void Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
              .WriteTo.File("tlsversioncheck.log")
              .WriteTo.Console()
              .CreateLogger();

            var serviceCollection = new ServiceCollection();
            ConfigureServices(serviceCollection);

            var serviceProvider = serviceCollection.BuildServiceProvider();

            ILogger<TlsVersionChecker> log = serviceProvider.GetService<ILogger<TlsVersionChecker>>();

            log.LogInformation("Log init");
            if (args.Length != 1)
            {
                log.LogError("Invalid arg count");
            }
            else
            {
                string server = args[0];
                log.LogInformation($"will connect to server:{server}");
                TlsVersionChecker vc = new TlsVersionChecker(log);
                vc.TryAllProtocols(server);
            }
        }

        private static void ConfigureServices(IServiceCollection services)
        {
            services.AddLogging(configure => configure.AddSerilog());
        }
    }
}
