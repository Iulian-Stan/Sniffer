using System;
using System.IO;
using System.Net;
using System.Windows.Forms;

namespace Sniffer
{
    public class AntetTCP
    {
        //cimpurile header-ului TCP
        private ushort _16_SourcePort;                  //16 biti pt portu sursei
        private ushort _16_DestinationPort;             //16 bibi pt portul destinatiei
        private uint _32_SequenceNumber = 555;          //32 biti pt numarul secventei
        private uint _32_AcknowledgementNumber = 555;   //32 biti pt numarul de recunoastere
        private ushort _16_DataOffsetAndFlags = 555;    //16 biti pr flag-uri si offset
        private ushort _16_Window = 555;                //16 biti pt dimensiunea ferestrei
        private short _16_Checksum = 555;               //16 biti pr CRC (poate fi negativ)
        private ushort _16_UrgentPointer;               //16 biti pt urgent pointer


        private byte hLength;                           //lungimea header-ului
        private ushort mLength;                         //lungimea informatiei
        private byte[] tcpData = new byte[8192];        //continutul informatiei din pachetul TCP

        public AntetTCP(byte[] myBuffer, int nReceived)
        {

            MemoryStream mS = new MemoryStream(myBuffer, 0, nReceived);
            BinaryReader bR = new BinaryReader(mS);

            //16 biti pt portu sursei
            _16_SourcePort = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //16 bibi pt portul destinatiei
            _16_DestinationPort = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //32 biti pt numarul secventei
            _32_SequenceNumber = (uint)IPAddress.NetworkToHostOrder(bR.ReadInt32());

            //32 biti pt numarul de recunoastere
            _32_AcknowledgementNumber = (uint)IPAddress.NetworkToHostOrder(bR.ReadInt32());

            //16 biti pr flag-uri si offset
            _16_DataOffsetAndFlags = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //16 biti pt dimensiunea ferestrei
            _16_Window = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //16 biti pr CRC (poate fi negativ)
            _16_Checksum = (short)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //16 biti pt urgent pointer
            _16_UrgentPointer = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //offsetul indica inceputul informatiei deci putem calcula lunfimea header-ului
            hLength = (byte)(_16_DataOffsetAndFlags >> 12);
            hLength *= 4;

            //lungimea mesaj = lungimea totala a pachetului TCP - lungimea header
            mLength = (ushort)(nReceived - hLength);

            //copiem mesajul intr-un buffer
            Array.Copy(myBuffer, hLength, tcpData, 0, nReceived - hLength);
        }

        public string SourcePort
        {
            get
            {
                return _16_SourcePort.ToString();
            }
        }

        public string DestinationPort
        {
            get
            {
                return _16_DestinationPort.ToString();
            }
        }

        public string SequenceNumber
        {
            get
            {
                return _32_SequenceNumber.ToString();
            }
        }

        public string AcknowledgementNumber
        {
            get
            {
                //daca flagul ACK este setat avem o valoare valida 
                //pt numarul de confirmare , deci il verificam
                if ((_16_DataOffsetAndFlags & 0x10) != 0)
                {
                    return _32_AcknowledgementNumber.ToString();
                }
                else
                    return "";
            }
        }

        public string HeaderLength
        {
            get
            {
                return hLength.ToString();
            }
        }

        public string WindowSize
        {
            get
            {
                return _16_Window.ToString();
            }
        }

        public string UrgentPointer
        {
            get
            {
                //daca flagul URG este setat avem o valoare valida 
                //pt urgent pointer , deci il verificam
                if ((_16_DataOffsetAndFlags & 0x20) != 0)
                {
                    return _16_UrgentPointer.ToString();
                }
                else
                    return "";
            }
        }

        public string Flags
        {
            get
            {
                //primii 6 MSB contin biti de control 

                //initial extragem flag-urile
                int nFlags = _16_DataOffsetAndFlags & 0x3F;

                string strFlags = string.Format("0x{0:x2} (", nFlags);

                if ((nFlags & 0x01) != 0)
                {
                    strFlags += "FIN, ";
                }
                if ((nFlags & 0x02) != 0)
                {
                    strFlags += "SYN, ";
                }
                if ((nFlags & 0x04) != 0)
                {
                    strFlags += "RST, ";
                }
                if ((nFlags & 0x08) != 0)
                {
                    strFlags += "PSH, ";
                }
                if ((nFlags & 0x10) != 0)
                {
                    strFlags += "ACK, ";
                }
                if ((nFlags & 0x20) != 0)
                {
                    strFlags += "URG";
                }
                strFlags += ")";

                if (strFlags.Contains("()"))
                {
                    strFlags = strFlags.Remove(strFlags.Length - 3);
                }
                else if (strFlags.Contains(", )"))
                {
                    strFlags = strFlags.Remove(strFlags.Length - 3, 2);
                }

                return strFlags;
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

        public byte[] Data
        {
            get
            {
                return tcpData;
            }
        }

        public ushort MessageLength
        {
            get
            {
                return mLength;
            }
        }
    }
}