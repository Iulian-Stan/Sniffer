using System.IO;
using System.Net;

namespace Sniffer
{
    public class AntetDNS
    {
        //cimpurile header-ului DNS
        private ushort _16_Identification;        //16 biti pt identificare
        private ushort _16_Flags;                 //16 biti pt flag-uri
        private ushort _16_TotalQuestions;        //16 biti pt numarul de interogari
        private ushort _16_TotalAnswerRRs;        //16 biti pt numarul de raspunsuri
        private ushort _16_TotalAuthorityRRs;     //16 biti pt autoritate
        private ushort _16_TotalAdditionalRRs;    //16 biti pt auxiliare

        public AntetDNS(byte[] myBuffer, int nReceived)
        {
            MemoryStream mS = new MemoryStream(myBuffer, 0, nReceived);
            BinaryReader bR = new BinaryReader(mS);

            //primii 16 biti sunt pt indentificare
            _16_Identification = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //urmatorii contin flag-uri
            _16_Flags = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //citeste numarul de intrebari
            _16_TotalQuestions = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //citeste numarul de raspunsuri
            _16_TotalAnswerRRs = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //citeste autoritatile
            _16_TotalAuthorityRRs = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());

            //citeste resurse audagatoare
            _16_TotalAdditionalRRs = (ushort)IPAddress.NetworkToHostOrder(bR.ReadInt16());
        }

        public string Identification
        {
            get
            {
                return string.Format("0x{0:x2}", _16_Identification);
            }
        }

        public string Flags
        {
            get
            {
                return string.Format("0x{0:x2}", _16_Flags);
            }
        }

        public string TotalQuestions
        {
            get
            {
                return _16_TotalQuestions.ToString();
            }
        }

        public string TotalAnswerRRs
        {
            get
            {
                return _16_TotalAnswerRRs.ToString();
            }
        }

        public string TotalAuthorityRRs
        {
            get
            {
                return _16_TotalAuthorityRRs.ToString();
            }
        }

        public string TotalAdditionalRRs
        {
            get
            {
                return _16_TotalAdditionalRRs.ToString();
            }
        }
    }
}
