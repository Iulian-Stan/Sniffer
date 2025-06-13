using System;
using System.IO;
using System.Net;

namespace NetworkSniffer
{
    /// <summary>
    /// IP header fields
    /// </summary>
    public class HeaderIP
    {
        /// <summary>
        /// 8 biti pt versiune si lungimea headerului
        /// </summary>
        private readonly byte _VersionAndHeaderLength;
        /// <summary>
        /// 8 bit type os service
        /// </summary>
        private readonly byte _TypeOfServcice;
        /// <summary>
        /// 16 bit total datagram length (header + _Data)
        /// </summary>
        private readonly ushort _TotalLength;
        /// <summary>
        /// 16 bit pt identification
        /// </summary>
        private readonly ushort _Identification;
        /// <summary>
        /// 16 bit flags and datagram offset
        /// </summary>
        private readonly ushort _FlagsAndOffset;
        /// <summary>
        /// 8 bit time to live
        /// </summary>
        private readonly byte _TimeToLive;
        /// <summary>
        /// 8 bit next level protocol
        /// </summary>
        private readonly byte _Protocol;
        /// <summary>
        /// 16 biti checksum
        /// </summary>
        private readonly short _Checksum;
        /// <summary>
        /// 32 biti source IP address
        /// </summary>
        private readonly uint _SourceAddress;
        /// <summary>
        /// 32 biti destination IP address
        /// </summary>
        private readonly uint _DestinationAddress;
        /// <summary>
        /// 4 bit header length
        /// </summary>
        private readonly byte _HeaderLength;
        /// <summary>
        /// IP packet Data
        /// </summary>
        private readonly byte[] _Data;

        public HeaderIP(byte[] myBuffer, int nReceived)
        {

            MemoryStream mS = new (myBuffer, 0, nReceived);
            BinaryReader bR = new (mS);

            _VersionAndHeaderLength = bR.ReadByte();
            _TypeOfServcice = bR.ReadByte();
            _TotalLength = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());
            _Identification = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());
            _FlagsAndOffset = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());
            _TimeToLive = bR.ReadByte();
            _Protocol = bR.ReadByte();
            _Checksum = IPAddress.NetworkToHostOrder(bR.ReadInt16());
            _SourceAddress = bR.ReadUInt32();
            _DestinationAddress = bR.ReadUInt32();

            _HeaderLength = (byte)((_VersionAndHeaderLength & 0xF) << 2);

            // copy the data that follows after the header
            if (_TotalLength - _HeaderLength > 0)
            {
                _Data = new byte[_TotalLength - _HeaderLength];
                Array.Copy(myBuffer, _HeaderLength, _Data, 0, _TotalLength - _HeaderLength);
            }
            else
            {
                System.Diagnostics.Trace.TraceError("Invalid packet length.");
            }
        }

        public string Version
        {
            get
            {
                if ((_VersionAndHeaderLength >> 4) == 4)
                {
                    return "IP v4";
                }
                else if ((_VersionAndHeaderLength >> 4) == 6)
                {
                    return "IP v6";
                }
                else
                {
                    return "Unknown";
                }
            }
        }

        public string HeaderLength
        {
            get
            {
                return _HeaderLength.ToString();
            }
        }

        public ushort MessageLength
        {
            get
            {
                return (ushort)(_TotalLength - _HeaderLength);
            }
        }

        public string TypeOfService
        {
            get
            {
                return string.Format("0x{0:x2} ({1})", _TypeOfServcice, _TypeOfServcice);
            }
        }

        public string Flags
        {
            get
            {
                int flags = _FlagsAndOffset >> 13;
                return flags.ToString();
            }
        }

        public string FragmentOffset
        {
            get
            {
                int nOffset = _FlagsAndOffset & 0x1FFF;
                return nOffset.ToString();
            }
        }

        public string TimeToLive
        {
            get
            {
                return _TimeToLive.ToString();
            }
        }

        public Protocol Protocol
        {
            get
            {
                if (_Protocol == 1)
                {
                    return Protocol.ICMP;
                }
                else if (_Protocol == 6)
                {
                    return Protocol.TCP;
                }
                else if (_Protocol == 17)
                {
                    return Protocol.UDP;
                }
                else
                {
                    return Protocol.Unknown;
                }
            }
        }

        public string Checksum
        {
            get
            {
                return string.Format("0x{0:x2}", _Checksum);
            }
        }

        public IPAddress SourceAddress
        {
            get
            {
                return new IPAddress(_SourceAddress);
            }
        }

        public IPAddress DestinationAddress
        {
            get
            {
                return new IPAddress(_DestinationAddress);
            }
        }

        public string TotalLength
        {
            get
            {
                return _TotalLength.ToString();
            }
        }

        public string Identification
        {
            get
            {
                return _Identification.ToString();
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
