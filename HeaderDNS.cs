using System.IO;
using System.Net;

namespace NetworkSniffer
{
    /// <summary>
    /// DNS header fields
    /// </summary>
    public class HeaderDNS
    {
        /// <summary>
        /// 16 bit identifier 
        /// </summary>
        private readonly ushort _Identifier;
        /// <summary>
        /// 16 bit flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
        /// </summary>
        private readonly ushort _Flags;
        /// <summary>
        /// 16 bit number of entries in the question section
        /// </summary>
        private readonly ushort _QuestionsCount;
        /// <summary>
        /// 16 bit number of resource records in the answer section
        /// </summary>
        private readonly ushort _AnswersCount;
        /// <summary>
        /// 16 bit number of name server resource records in authority records
        /// </summary>
        private readonly ushort _NameServersCount;
        /// <summary>
        /// 16 biti number of resource records in the additional records section
        /// </summary>
        private readonly ushort _AdditionalRecordsCount;

        public HeaderDNS(byte[] myBuffer, int nReceived)
        {
            MemoryStream mS = new (myBuffer, 0, nReceived);
            BinaryReader bR = new (mS);

            _Identifier = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());
            _Flags = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());
            _QuestionsCount = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());
            _AnswersCount = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());
            _NameServersCount = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());
            _AdditionalRecordsCount = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());
        }

        public string Identifier
        {
            get
            {
                return string.Format("0x{0:x2}", _Identifier);
            }

        }

        public string Flags
        {
            get
            {
                return string.Format("0x{0:x2}", _Flags);
            }
        }

        public string QuestionsCount
        {
            get
            {
                return _QuestionsCount.ToString();
            }
        }

        public string AnswersCount
        {
            get
            {
                return _AnswersCount.ToString();
            }
        }

        public string NameServersCount
        {
            get
            {
                return _NameServersCount.ToString();
            }
        }

        public string AdditionalRecordsCount
        {
            get
            {
                return _AdditionalRecordsCount.ToString();
            }
        }
    }
}
