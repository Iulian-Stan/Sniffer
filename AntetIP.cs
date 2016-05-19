using System;
using System.IO;
using System.Net;
using System.Windows.Forms;

namespace Sniffer
{
    public class AntetIP
    {
        //cimpurile header-ului IP
        private byte _8_VersionAndHeaderLength;   //8 biti pt versiune si lungimea headerului
        private byte _8_DifferentiatedServices;   //8 biti pt servicii diferentiate (TOS)
        private ushort _16_TotalLength;           //16 biti pt lungimea totala a datagramei (header + mesaj)
        private ushort _16_Identification;        //16 biti pt identificare
        private ushort _16_FlagsAndOffset;        //16 biti pt flaguri si offset de fragmentare
        private byte _8_TTL;                      //8 biti pt TTL (Time To Live)
        private byte _8_Protocol;                 //8 biti pt protocolul incapsulat
        private short _16_Checksum;               //16 biti CRC header-ului (poate fi si negativa deci e short)
        private uint _32_SourceIPAddress;         //32 biti adresa IP a sursei
        private uint _32_DestinationIPAddress;    //32 biti adresa IP a destinatiei

        private byte hLength;                     //lungimea header-ului
        private byte[] ipData = new byte[8192];   //data din datagrama


        public AntetIP(byte[] myBuffer, int nReceived)
        {

            MemoryStream mS = new MemoryStream(myBuffer, 0, nReceived);
            BinaryReader bR = new BinaryReader(mS);

            //8 biti pt versiune si lungimea headerului
            _8_VersionAndHeaderLength = bR.ReadByte();

            //8 biti pt servicii diferentiate (TOS)
            _8_DifferentiatedServices = bR.ReadByte();

            //16 biti pt lungimea totala a datagramei
            _16_TotalLength = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //16 biti pt identificare
            _16_Identification = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //16 biti pt flaguri si offset de fragmentare
            _16_FlagsAndOffset = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //8 biti pt TTL (Time To Live)
            _8_TTL = bR.ReadByte();

            //8 biti pt protocolul incapsulat
            _8_Protocol = bR.ReadByte();

            //16 biti CRC header-ului (poate fi si negativa deci e short)
            _16_Checksum = IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //32 biti adresa IP a sursei
            _32_SourceIPAddress = (uint)(bR.ReadInt32());

            //32 biti adresa IP a destinatiei
            _32_DestinationIPAddress = (uint)(bR.ReadInt32());

            //Calculeaz lungimea header-ului
            hLength = _8_VersionAndHeaderLength;

            //excludem 4 MSB ce contin versiunea
            hLength <<= 4;
            hLength >>= 4;

            //4 LSB contin lungimea in cuvinte de 32 biti (4 cteti)
            hLength *= 4;

            //copiem data continuta in datagrama
            //incepem de la sfirsitul header-ului
            Array.Copy(myBuffer, hLength, ipData, 0, _16_TotalLength - hLength);
        }

        public string Version
        {
            get
            {
                //Determinam versiunea 

                //4 MSB contin header-ul
                if ((_8_VersionAndHeaderLength >> 4) == 4)
                {
                    return "IP v4";
                }
                else if ((_8_VersionAndHeaderLength >> 4) == 6)
                {
                    return "IP v6";
                }
                else
                {
                    return "Necunoscut";
                }
            }
        }

        public string HeaderLength
        {
            get
            {
                return hLength.ToString();
            }
        }

        public ushort MessageLength
        {
            get
            {
                //Lungimea mesajului = lungimea totala - lungimea header-ului
                return (ushort)(_16_TotalLength - hLength);
            }
        }

        public string DifferentiatedServices
        {
            get
            {
                //returnam serviciile diferentiate in format hexazecimal
                return string.Format("0x{0:x2} ({1})", _8_DifferentiatedServices,
                    _8_DifferentiatedServices);
            }
        }

        public string Flags
        {
            get
            {
                //primii 3 MSB indica daca informatia e fragmentata
                int nFlags = _16_FlagsAndOffset >> 13;
                if (nFlags == 2)
                {
                    return "Continut intreg";
                }
                else if (nFlags == 1)
                {
                    return "Mai vin fragmente";
                }
                else
                {
                    return nFlags.ToString();
                }
            }
        }

        public string FragmentationOffset
        {
            get
            {
                //ceilalti 13 biti contin offset-ul fragmentarii 
                //contain the fragmentation offset
                int nOffset = _16_FlagsAndOffset << 3;
                nOffset >>= 3;

                return nOffset.ToString();
            }
        }

        public string TTL
        {
            get
            {
                return _8_TTL.ToString();
            }
        }

        public Protocol ProtocolType
        {
            get
            {
                if (_8_Protocol == 1)             //1 === protocol ICMP
                {
                    return Protocol.ICMP;
                }
                else if (_8_Protocol == 6)        //6 === protocol TCP
                {
                    return Protocol.TCP;
                }
                else if (_8_Protocol == 17)       //17 === protocol UDP
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
                //returnam CRC-ul
                return string.Format("0x{0:x2}", _16_Checksum);
            }
        }

        public IPAddress SourceAddress
        {
            get
            {
                return new IPAddress(_32_SourceIPAddress);
            }
        }

        public IPAddress DestinationAddress
        {
            get
            {
                return new IPAddress(_32_DestinationIPAddress);
            }
        }

        public string TotalLength
        {
            get
            {
                return _16_TotalLength.ToString();
            }
        }

        public string Identification
        {
            get
            {
                return _16_Identification.ToString();
            }
        }

        public byte[] Data
        {
            get
            {
                return ipData;
            }
        }
    }
}
