using System;
using System.IO;
using System.Net;

namespace NetworkSniffer
{
    /// <summary>
    /// USP header fields
    /// </summary>
    public class HeaderUDP
    {
        /// <summary>
        /// 16 bit source port       
        /// </summary>
        private readonly ushort _SourcePort;
        /// <summary>
        /// 16 bib destination Port
        /// </summary>
        private readonly ushort _DestinationPort;
        /// <summary>
        /// 16 bit header length
        /// </summary>
        private readonly ushort _Length;
        /// <summary>
        /// 16 bit checksum            
        /// </summary>
        private readonly short _Checksum;

        /// <summary>
        /// USP packet data
        /// </summary>
        private readonly byte[] _Data = new byte[8192];

        public HeaderUDP(byte[] myBuffer, int nReceived)
        {
            MemoryStream mS = new (myBuffer, 0, nReceived);
            BinaryReader bR = new (mS);

            _SourcePort = (ushort)IPAddress.NetworkToHostOrder(bR.ReadUInt16());
            _DestinationPort = (ushort)IPAddress.NetworkToHostOrder(bR.ReadUInt16());
            _Length = (ushort)IPAddress.NetworkToHostOrder(bR.ReadUInt16());
            _Checksum = (short)IPAddress.NetworkToHostOrder(bR.ReadUInt16());

            // copy the data that follows after the header
            Array.Copy(myBuffer, 8, _Data, 0, nReceived - 8);
        }

        public string SourcePort
        {
            get
            {
                return _SourcePort.ToString();
            }
        }

        public string DestinationPort
        {
            get
            {
                return _DestinationPort.ToString();
            }
        }

        public string Length
        {
            get
            {
                return _Length.ToString();
            }
        }

        public string Checksum
        {
            get
            {
                return string.Format("0x{0:x2}", _Checksum);
            }
        }

        public byte[] Data
        {
            get
            {
                return _Data;
            }
        }
    }
}