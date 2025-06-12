using System.IO;
using System.Net;

namespace NetworkSniffer
{
    /// <summary>
    /// ICMP header fields
    /// </summary>
    public class HeaderICMP
    {
        /// <summary>
        /// 8 bit type
        /// </summary>
        private readonly byte _Type;
        /// <summary>
        /// 8 bit Code
        /// </summary>
        private readonly byte _Code;
        /// <summary>
        /// 16 bit checksum
        /// </summary>
        private readonly short _Checksum;  

        public HeaderICMP(byte[] myBuffer, int nReceived)
        {
            MemoryStream mS = new (myBuffer, 0, nReceived);
            BinaryReader bR = new (mS);

            _Type = bR.ReadByte();
            _Code = bR.ReadByte();
            _Checksum = IPAddress.NetworkToHostOrder(bR.ReadInt16());
        }

        public string Type
        {
            get
            {
                return _Type.ToString();
            }
        }

        public string Code
        {
            get
            {
                return _Code.ToString();
            }
        }

        public string Checksum
        {
            get
            {
                return string.Format("0x{0:x2}", _Checksum);
            }
        }

        public string Message
        {
            get
            {
                string s = "Unknown";
                switch (_Type)
                {
                    case 0: return "Echo Replay";
                    case 3:
                        s = "Destination Unreachable";
                        return _Code switch
                        {
                            0 => s + " : Network Unreachable",
                            1 => s + " : Host Unreachable",
                            2 => s + " : Protocol Unreachable",
                            3 => s + " : Port Unreachable",
                            4 => s + " : Fragment Necessary",
                            5 => s + " : Fragment Necessary",
                            6 => s + " : Destination Network Unknown",
                            7 => s + " : Destination Host Unknown",
                            8 => s + " : Obsolete",
                            9 => s + " : Destination Network Prohibited",
                            10 => s + " : Destination Host Prohibited",
                            11 => s + " : Network Unreachable for TOS",
                            12 => s + " : Host Unreachable for TOS",
                            13 => s + " : Communication Prohibited",
                            _ => s,
                        };
                    case 4: return "Source Quench";
                    case 5:
                        s = "Redirect";
                        return _Code switch
                        {
                            0 => s + " : Redirect for Network",
                            1 => s + " : Redirect for Host",
                            2 => s + " : Rediretc TOS and Network",
                            3 => s + " : Redirect TOS and Host",
                            _ => s,
                        };
                    case 8: return "Echo Request";
                    case 9: return "Router advertisement";
                    case 10: return "Router Solicitation";
                    case 11:
                        s = "Time to Live exceeded";
                        return _Code switch
                        {
                            0 => s + " : TTL Exceeded in Transit",
                            1 => s + " : TTL Exceeded in Reassembly",
                            _ => s,
                        };
                    case 12:
                        s = "Parameter Problem";
                        return _Code switch
                        {
                            0 => s + " : Pointer Poblem",
                            1 => s + " : Required Option Missing",
                            _ => s,
                        };
                    case 13: return "Timestam request";
                    case 14: return "Timestamp Replay";
                    case 17: return "Address Mask Request";
                    case 18: return "Address Mask Replay";
                }
                return s;
            }
        }
    }
}
