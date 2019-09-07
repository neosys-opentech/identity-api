using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;

namespace Identity
{
    /// <summary>
    /// startup class
    /// </summary>
    public class Program
    {
        /// <summary>
        /// main method
        /// </summary>
        /// <param name="args">argument list</param>
        public static void Main(string[] args)
        {
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>().Build().Run();
        }   
    }
}
