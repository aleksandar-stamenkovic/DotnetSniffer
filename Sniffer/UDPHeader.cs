using System.Net;
using System.Text;
using System;
using System.IO;

namespace Sniffer
{
    public class UDPHeader
    {
        //UDP header fields
        private ushort _sourcePort;                //16 bits for the source port number        
        private ushort _destinationPort;           //16 bits for the destination port number
        private ushort _length;                    //Length of the UDP header
        private short  _checksum;                  //16 bits for the checksum
                                                   //(checksum can be negative so taken as short)              
        //End UDP header fields

        private byte[] _UDPData = new byte[4096];  //Data carried by the UDP packet

        public UDPHeader(byte [] byBuffer, int nReceived)
        {
            MemoryStream memoryStream = new MemoryStream(byBuffer, 0, nReceived);
            BinaryReader binaryReader = new BinaryReader(memoryStream);

            //The first sixteen bits contain the source port
            _sourcePort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //The next sixteen bits contain the destination port
            _destinationPort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //The next sixteen bits contain the length of the UDP packet
            _length = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //The next sixteen bits contain the checksum
            _checksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());            

            //Copy the data carried by the UDP packet into the data buffer
            Array.Copy(byBuffer, 
                       8,               //The UDP header is of 8 bytes so we start copying after it
                       _UDPData, 
                       0, 
                       nReceived - 8);
        }

        public string SourcePort
        {
            get
            {
                return _sourcePort.ToString();
            }
        }

        public string DestinationPort
        {
            get
            {
                return _destinationPort.ToString();
            }
        }

        public string Length
        {
            get
            {
                return _length.ToString ();
            }
        }

        public string Checksum
        {
            get
            {
                //Return the checksum in hexadecimal format
                return string.Format("0x{0:x2}", _checksum);
            }
        }

        public byte[] Data
        {
            get
            {
                return _UDPData;
            }
        }

        public override string ToString()
        {
            string value = "";
            value += "UDP\n";
            value += $"Source Port: {SourcePort}\n";
            value += $"Destination Port: {DestinationPort}\n";
            value += $"Length: {Length}\n";
            value += $"Checksum: {Checksum}\n";

            return value;
        }
    }
}