using System.IO;
using System.Net;

namespace Sniffer
{
    public class AntetICMP
    {
        //cimpurile header-ului IP
        private byte _8_ICMPType;                //8 biti pt tip ICMP
        private byte _8_CodeType;                //8 biti pt tipul codului
        private short _16_Checksum;              //16 biti pr CRC (poate fi negativ)       

        public AntetICMP(byte[] myBuffer, int nReceived)
        {
            MemoryStream mS = new MemoryStream(myBuffer, 0, nReceived);
            BinaryReader bR = new BinaryReader(mS);

            //8 biti pt tip ICMP
            _8_ICMPType = bR.ReadByte();

            //8 biti pt tipul codului
            _8_CodeType = bR.ReadByte();

            //16 biti CRC header-ului (poate fi si negativa deci e short)
            _16_Checksum = IPAddress.NetworkToHostOrder(bR.ReadInt16());
        }

        public string ICMPType
        {
            get
            {
                return _8_ICMPType.ToString();
            }
        }

        public string CodeType
        {
            get
            {
                return _8_CodeType.ToString();
            }
        }

        public string Checksum
        {
            get
            {
                //returnam CRC in format hexazecimal
                return string.Format("0x{0:x2}", _16_Checksum);
            }
        }

        public string Message()
        {
            string s = "Unknown";
            switch (_8_ICMPType)
            {
                case 0: return "Echo Replay";
                case 3: s = "Destination Unreachable";
                    switch (_8_CodeType)
                    {
                        case 0: return s + " : Network Unreachable";
                        case 1: return s + " : Host Unreachable";
                        case 2: return s + " : Protocol Unreachable";
                        case 3: return s + " : Port Unreachable";
                        case 4: return s + " : Fragment Necessary";
                        case 5: return s + " : Fragment Necessary";
                        case 6: return s + " : Destination Network Unknown";
                        case 7: return s + " : Destination Host Unknown";
                        case 8: return s + " : Obsolete";
                        case 9: return s + " : Destination Network Prohibited";
                        case 10: return s + " : Destination Host Prohibited";
                        case 11: return s + " : Network Unreachable for TOS";
                        case 12: return s + " : Host Unreachable for TOS";
                        case 13: return s + " : Communication Prohibited";
                    }
                    return s;
                case 4: return "Source Quench";
                case 5: s =  "Redirect";
                     switch (_8_CodeType)
                    {
                        case 0: return s + " : Redirect for Network";
                        case 1: return s + " : Redirect for Host";
                        case 2: return s + " : Rediretc TOS and Network";
                        case 3: return s + " : Redirect TOS and Host";
                    }
                    return s;
                case 8: return "Echo Request";
                case 9: return "Router advertisement";
                case 10: return "Router Solicitation";
                case 11: s = "Time to Live exceeded";
                    switch (_8_CodeType)
                    {
                        case 0: return s + " : TTL Exceeded in Transit";
                        case 1: return s + " : TTL Exceeded in Reassembly";
                    }
                    return s;
                case 12: s = "Parameter Problem";
                    switch (_8_CodeType)
                    {
                        case 0: return s + " : Pointer Poblem";
                        case 1: return s + " : Required Option Missing";
                    }
                    return s;
                case 13: return "Timestam request";
                case 14: return "Timestamp Replay";
                case 17: return "Address Mask Request";
                case 18: return "Address Mask Replay";
            }
            return s;
        }
    }
}
