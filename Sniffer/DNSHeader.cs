using System.Net;
using System.Text;
using System;
using System.IO;
using System.Collections.Specialized;
using System.Collections;
using System.Collections.Generic;

namespace Sniffer
{
    public class DNSHeader
    {
        //DNS header fields
        private ushort _identification;         //16 bits for identification
        private ushort _flags;                  //16 bits for DNS flags
        private ushort _totalQuestions;         //16 bits indicating the number of entries 
                                                //in the questions list
        private ushort _totalAnswerRRs;         //16 bits indicating the number of entries
                                                //entries in the answer resource record list
        private ushort _totalAuthorityRRs;      //16 bits indicating the number of entries
                                                //entries in the authority resource record list
        private ushort _totalAdditionalRRs;     //16 bits indicating the number of entries
                                                //entries in the additional resource record list
        //End DNS header fields

        public DNSHeader(byte []byBuffer, int nReceived)
        {
            MemoryStream memoryStream = new MemoryStream(byBuffer, 0, nReceived);
            BinaryReader binaryReader = new BinaryReader(memoryStream);    
   
            //First sixteen bits are for identification
            _identification = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //Next sixteen contain the flags
            _flags = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //Read the total numbers of questions in the quesion list
            _totalQuestions = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //Read the total number of answers in the answer list
            _totalAnswerRRs = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //Read the total number of entries in the authority list
            _totalAuthorityRRs = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //Total number of entries in the additional resource record list
            _totalAdditionalRRs = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
        }

        public string Identification
        {
            get
            {
                return string.Format("0x{0:x2}", _identification);
            }
        }

        public string Flags
        {
            get
            {
                return string.Format("0x{0:x2}", _flags);
            }
        }

        public string TotalQuestions
        {
            get
            {
                return _totalQuestions.ToString();
            }
        }

        public string TotalAnswerRRs
        {
            get
            {
                return _totalAnswerRRs.ToString();
            }
        }

        public string TotalAuthorityRRs
        {
            get
            {
                return _totalAuthorityRRs.ToString();
            }
        }

        public string TotalAdditionalRRs
        {
            get
            {
                return _totalAdditionalRRs.ToString();
            }
        }

        public override string ToString()
        {
            string value = "";
            value += "DNS\n";
            value += $"Identification: {Identification}\n";
            value += $"Flags: {Flags}\n";
            value += $"Questions: {TotalQuestions}\n";
            value += $"Answer RRs: {TotalAnswerRRs}\n";
            value += $"Authority RRs: {TotalAuthorityRRs}\n";
            value += $"Additional RRs: {TotalAdditionalRRs}\n";
            
            return value;
        }
    }
}
