using System;
using System.IO;
using System.Net;

namespace Sniffer
{
    public class AntetUDP
    {
        //cimpurile header-ului UDP
        private ushort _16_SourcePort;            //16 biti pt portu sursei       
        private ushort _16_DestinationPort;       //16 bibi pt portul destinatiei
        private ushort _16_Length;                //16 biti pr lungimea header-ului
        private short _16_Checksum;               //16 biti pr CRC (poate fi negativ)            

        private byte[] udpData = new byte[8192];  //datele continute in pachetul UDP

        public AntetUDP(byte[] myBuffer, int nReceived)
        {
            MemoryStream mS = new MemoryStream(myBuffer, 0, nReceived);
            BinaryReader bR = new BinaryReader(mS);

            //16 biti pt portu sursei 
            _16_SourcePort = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //16 bibi pt portul destinatiei
            _16_DestinationPort = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //16 biti pr lungimea header-ului
            _16_Length = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //16 biti pr CRC (poate fi negativ)  
            _16_Checksum = IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //copiem datele din pachet intr-un buffer
            //lungimea header-ului e de 8 octeti
            Array.Copy(myBuffer, 8, udpData, 0, nReceived - 8);
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

        public string Length
        {
            get
            {
                return _16_Length.ToString();
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
                return udpData;
            }
        }
    }
}