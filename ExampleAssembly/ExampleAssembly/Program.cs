using System;
using System.Diagnostics;

namespace ExampleAssembly
{
    class Program
    {
        static void Main(string[] args)
        {
            Process.Start(new ProcessStartInfo("calc.exe"));
            Console.WriteLine("Hello from .NET!");
        }
    }
}
