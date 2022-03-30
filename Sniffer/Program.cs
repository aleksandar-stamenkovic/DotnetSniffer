using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Sniffer
{
    internal class Program
    {
        static Socket socket;
        static byte[] byteData = new byte[4096];
        //static string chosenProtocol = "";
        static bool[] chosenProtocols = { false, false, false, false }; // IP, TCP, UDP, DNS

        static void Main(string[] args)
        {
            Console.WriteLine("Choose the IP address:");

            IPHostEntry hostEntry = Dns.GetHostEntry(Dns.GetHostName());

            if(hostEntry.AddressList.Length > 0)
            {
                for(var i = 0; i < hostEntry.AddressList.Length; i++)
                {
                    Console.Write(i + ": ");
                    Console.WriteLine(hostEntry.AddressList[i]);
                }
            }

            var inputNumber = int.Parse(Console.ReadLine());
            var ipAddress = hostEntry.AddressList[inputNumber];

            ChooseTheProtocol();

            socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            socket.Bind(new IPEndPoint(IPAddress.Parse(ipAddress.ToString()), 0));

            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

            byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
            byte[] byOut = new byte[4] { 1, 0, 0, 0 };

            socket.IOControl(IOControlCode.ReceiveAll, byTrue, byOut);

            socket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);

            while (true) { } // Prevent from closing the prompt
        }

        private static void ChooseTheProtocol()
        {
            Console.WriteLine("Choose the protocol:");
            Console.WriteLine("You can choose multiple protocols by selecting more numbers.");
            Console.WriteLine("For example, if you want to choose IP and UDP you can type: 02");
            Console.WriteLine("0: IP");
            Console.WriteLine("1: TCP");
            Console.WriteLine("2: UDP");
            Console.WriteLine("3: DNS");
            var input = Console.ReadLine();

            ArgumentNullException.ThrowIfNull(input);

            if (input.Contains("0")) chosenProtocols[0] = true;
            if (input.Contains("1")) chosenProtocols[1] = true;
            if (input.Contains("2")) chosenProtocols[2] = true;
            if (input.Contains("3")) chosenProtocols[3] = true;
        }

        private static void OnReceive(IAsyncResult ar)
        {
            int nReceived = socket.EndReceive(ar);
            ParseAndPrintData(byteData, nReceived);
            byteData = new byte[4096];

            socket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                        new AsyncCallback(OnReceive), null);
        }

        private static void ParseAndPrintData(byte[] byteData, int nReceived)
        {
            IPHeader ipHeader = new IPHeader(byteData, nReceived);
            if(chosenProtocols[0]) // IP is chosen
                Console.WriteLine(ipHeader.ToString());

            switch(ipHeader.ProtocolType)
            {
                case Protocol.TCP:

                    TCPHeader tcpHeader = new TCPHeader(ipHeader.Data, ipHeader.MessageLength);
                    if (chosenProtocols[1])
                        Console.WriteLine(tcpHeader.ToString());

                    // Check if DNS
                    if(tcpHeader.DestinationPort == "53" || tcpHeader.SourcePort == "53")
                    {
                        DNSHeader dnsHeader = new DNSHeader(tcpHeader.Data, tcpHeader.MessageLength);
                        if(chosenProtocols[3])
                            Console.WriteLine(dnsHeader.ToString());
                    }
                    break;

                case Protocol.UDP:

                    UDPHeader udpHeader = new UDPHeader(ipHeader.Data, ipHeader.MessageLength);
                    if(chosenProtocols[2])
                        Console.WriteLine(udpHeader.ToString());

                    // Check if DNS
                    if (udpHeader.DestinationPort == "53" || udpHeader.SourcePort == "53")
                    {
                        DNSHeader dnsHeader = new DNSHeader(udpHeader.Data, int.Parse(udpHeader.Length) - 8);
                        if (chosenProtocols[3])
                            Console.WriteLine(dnsHeader.ToString());
                    }
                    break;

                case Protocol.Unknown:
                    break;
            }
        }
    }
}
