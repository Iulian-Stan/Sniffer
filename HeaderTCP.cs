using System;
using System.IO;
using System.Net;

namespace NetworkSniffer
{
    /// <summary>
    /// TCP header fields
    /// </summary>
    public class AntetTCP
    {
        /// <summary>
        /// 16 bit source port number
        /// </summary>
        private readonly ushort _SourcePort;
        /// <summary>
        /// 16 bib destination port number
        /// </summary>
        private readonly ushort _DestinationPort;
        /// <summary>
        /// 32 bit sequence number
        /// </summary>
        private readonly uint _SequenceNumber;
        /// <summary>
        /// 32 bit paknowledgement number
        /// </summary>
        private readonly uint _AcknowledgementNumber;
        /// <summary>
        /// 16 bit data offset and control bits
        /// </summary>
        private readonly ushort _DataOffsetAndControlBits;
        /// <summary>
        /// 16 bit window
        /// </summary>
        private readonly ushort _Window;
        /// <summary>
        /// 16 bit checksum
        /// </summary>
        private readonly short _Checksum;
        /// <summary>
        /// 16 biti urgent pointer
        /// </summary>
        private readonly ushort _UrgentPointer;

        /// <summary>
        /// Header length
        /// </summary>
        private readonly byte _HeaderLength;
        /// <summary>
        /// Data length
        /// </summary>
        private readonly ushort _DataLength;
        /// <summary>
        /// TCP Packet Data
        /// </summary>
        private readonly byte[] _Data;

        public AntetTCP(byte[] myBuffer, int nReceived)
        {

            MemoryStream mS = new (myBuffer, 0, nReceived);
            BinaryReader bR = new (mS);

            _SourcePort = (ushort)IPAddress.NetworkToHostOrder(bR.ReadUInt16());
            _DestinationPort = (ushort)IPAddress.NetworkToHostOrder(bR.ReadUInt16());
            _SequenceNumber = (uint)IPAddress.NetworkToHostOrder(bR.ReadUInt32());
            _AcknowledgementNumber = (uint)IPAddress.NetworkToHostOrder(bR.ReadUInt32());
            _DataOffsetAndControlBits = (ushort)IPAddress.NetworkToHostOrder(bR.ReadUInt16());
            _Window = (ushort)IPAddress.NetworkToHostOrder(bR.ReadUInt16());
            _Checksum = (short)IPAddress.NetworkToHostOrder(bR.ReadUInt16());
            _UrgentPointer = (ushort)IPAddress.NetworkToHostOrder(bR.ReadUInt16());

            _HeaderLength = (byte)((_DataOffsetAndControlBits >> 12) << 2);
            _DataLength = (ushort)(nReceived - _HeaderLength);

            // copy the data that follows after the header
            _Data = new byte[nReceived - _HeaderLength];
            Array.Copy(myBuffer, _HeaderLength, _Data, 0, nReceived - _HeaderLength);
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

        public string SequenceNumber
        {
            get
            {
                return _SequenceNumber.ToString();
            }
        }

        public string AcknowledgementNumber
        {
            get
            {
                // Acknowledgment number is valid only if ACK control bit is set
                if ((_DataOffsetAndControlBits & 0x10) != 0)
                {
                    return _AcknowledgementNumber.ToString();
                }
                else
                    return "";
            }
        }

        public string HeaderLength
        {
            get
            {
                return _HeaderLength.ToString();
            }
        }

        public string Window
        {
            get
            {
                return _Window.ToString();
            }
        }

        public string UrgentPointer
        {
            get
            {
                // Urgent pointer is valid only if URG control bit is set
                if ((_DataOffsetAndControlBits & 0x20) != 0)
                {
                    return _UrgentPointer.ToString();
                }
                else
                    return "";
            }
        }

        public string ControlBits
        {
            get
            {
                int controlBits = _DataOffsetAndControlBits & 0x3F;

                string controlBitsString = string.Format("0x{0:x2} (", controlBits);

                if ((controlBits & 0x01) != 0)
                {
                    controlBitsString += "FIN, ";
                }
                if ((controlBits & 0x02) != 0)
                {
                    controlBitsString += "SYN, ";
                }
                if ((controlBits & 0x04) != 0)
                {
                    controlBitsString += "RST, ";
                }
                if ((controlBits & 0x08) != 0)
                {
                    controlBitsString += "PSH, ";
                }
                if ((controlBits & 0x10) != 0)
                {
                    controlBitsString += "ACK, ";
                }
                if ((controlBits & 0x20) != 0)
                {
                    controlBitsString += "URG";
                }
                controlBitsString += ")";

                if (controlBitsString.Contains("()"))
                {
                    controlBitsString = controlBitsString[..^3];
                }
                else if (controlBitsString.Contains(", )"))
                {
                    controlBitsString = controlBitsString.Remove(controlBitsString.Length - 3, 2);
                }

                return controlBitsString;
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

        public ushort DataLength
        {
            get
            {
                return _DataLength;
            }
        }
    }
}