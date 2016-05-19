using System;
using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;

namespace Sniffer
{
    public enum Protocol
    {
        ICMP = 1,
        TCP = 6,
        UDP = 17,
        Unknown = -1
    };

    public partial class SnifferForm : Form
    {
        private Socket mySocket;                          //socket-ul ce prinde pachetele
        private byte[] dataBuffer = new byte[8192];
        private bool stateFlag = false;                   //flagul setat pt prinderea pachetelor
        private byte pachet = 15;
        private Action<TreeNode> AddTreeNode;

        //private delegate void AddTreeNode(TreeNode node);

        public SnifferForm()
        {
            InitializeComponent();
            AddTreeNode = new Action<TreeNode>(OnTreeNode_Add);
        }

        private void state(bool State)
        {
            if (State)
            {
                btnStart.Text = "&Stop";
                toolStripStatusLabel.Text = "Running";
                toolStripProgressBar.Style = ProgressBarStyle.Marquee;
            }
            else
            {
                btnStart.Text = "&Start";
                toolStripStatusLabel.Text = "Stopped";
                toolStripProgressBar.Style = ProgressBarStyle.Blocks;
            }
            stateFlag = State;
        }

        private void OnBtnStart_Click(object sender, EventArgs e)
        {
            if (cmbInterfaces.Text == "")
            {
                MessageBox.Show("Alegeti interfata pentru capturarea pachetelor.", "Sniffer",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            try
            {
                if (!stateFlag)
                {
                    //incepe capturarea pachetelor

                    state(true);

                    mySocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

                    //leagam sochetul de adresa selectata
                    mySocket.Bind(new IPEndPoint(IPAddress.Parse(cmbInterfaces.Text), 0));

                    //setam optiunile socketului
                    mySocket.SetSocketOption(SocketOptionLevel.IP,              //doar pt pachete IP
                                               SocketOptionName.HeaderIncluded, //include header-ul
                                               true);                           //optiuni

                    byte[] inBytes = new byte[4] { 1, 0, 0, 0 };
                    byte[] outBytes = new byte[4] { 1, 0, 0, 0 }; //prinde pachetele ce ies

                    //Socket.IOControl este analog metodei WSAIoctl din Winsock 2
                    mySocket.IOControl(IOControlCode.ReceiveAll,              //echivalent cu SIO_RCVALL din Winsock 2
                                         inBytes,
                                         outBytes);

                    //primirea asincrona a apchetelor
                    mySocket.BeginReceive(dataBuffer, 0, dataBuffer.Length, SocketFlags.None,
                        new AsyncCallback(OnData_Receive), null);
                }
                else
                {
                    state(false);
                    //inchiderea socket-ului
                    mySocket.Close();
                }
            }
            catch (SocketException ex)
            {
                MessageBox.Show(ex.Message + "\n" + "Probleme legate de socket !", "Sniffer",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

        }

        private void OnData_Receive(IAsyncResult ar)
        {
            try
            {
                int nReceived = mySocket.EndReceive(ar);

                //analizam pachetul capturat
                ParseData(dataBuffer, nReceived);

                if (stateFlag)
                {
                    dataBuffer = new byte[8192];

                    //continuarea capturarii
                    mySocket.BeginReceive(dataBuffer, 0, dataBuffer.Length, SocketFlags.None,
                        new AsyncCallback(OnData_Receive), null);
                }
            }
            catch (ObjectDisposedException)
            {
            }
            catch (SocketException se)
            {
                MessageBox.Show(se.Message + "\n" + "Probleme legate de receptie !", "Sniffer",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ParseData(byte[] byteData, int nReceived)
        {
            TreeNode rootNode = new TreeNode();

            //Intru cit toate pachetele is de tip ip , 
            //scoatem header-ul si determinam tipul pachetului
            AntetIP ipHeader = new AntetIP(byteData, nReceived);

            if ((pachet & 1) == 1)
            {
                TreeNode ipNode = MakeIPTreeNode(ipHeader);
                rootNode.Nodes.Add(ipNode);
            }

            //acum analizam continutul 
            switch (ipHeader.ProtocolType)
            {
                case Protocol.ICMP:

                    AntetICMP icmpHeader = new AntetICMP(ipHeader.Data,             //data continuta in pachetul IP
                                                        ipHeader.MessageLength);    //lungimea datei                    
                    if ((pachet & 2) == 2)
                    {
                        TreeNode icmpNode = MakeICMPTreeNode(icmpHeader);

                        rootNode.Nodes.Add(icmpNode);
                    }
                    break;

                case Protocol.TCP:

                    AntetTCP tcpHeader = new AntetTCP(ipHeader.Data,              //data continuta in pachetul IP
                                                        ipHeader.MessageLength);    //lungimea datei                    
                    if ((pachet & 4) == 4)
                    {
                        TreeNode tcpNode = MakeTCPTreeNode(tcpHeader);

                        rootNode.Nodes.Add(tcpNode);
                    }
                    //daca portul este 53 , atunci protocolul de nivel inferior este DNS
                    //DNS suporta ambele protocoale de aceea testam de 2 ori
                    if ((tcpHeader.DestinationPort == "53" || tcpHeader.SourcePort == "53") && (pachet & 16) == 16)
                    {
                        TreeNode dnsNode = MakeDNSTreeNode(tcpHeader.Data, (int)tcpHeader.MessageLength);
                        rootNode.Nodes.Add(dnsNode);
                    }

                    break;

                case Protocol.UDP:

                    AntetUDP udpHeader = new AntetUDP(ipHeader.Data,              //pachetul UDP continut de IP
                                                       (int)ipHeader.MessageLength);//lungimea pachetului                  
                    if ((pachet & 8) == 8)
                    {
                        TreeNode udpNode = MakeUDPTreeNode(udpHeader);

                        rootNode.Nodes.Add(udpNode);
                    }
                    //daca portul este 53 , atunci protocolul de nivel inferior este DNS
                    //DNS suporta ambele protocoale de aceea testam de 2 ori
                    if ((udpHeader.DestinationPort == "53" || udpHeader.SourcePort == "53") && (pachet & 16) == 16)
                    {

                        TreeNode dnsNode = MakeDNSTreeNode(udpHeader.Data, Convert.ToInt32(udpHeader.Length) - 8);
                        rootNode.Nodes.Add(dnsNode);
                    }

                    break;

                case Protocol.Unknown:
                    break;
            }
            if (rootNode.Nodes.Count != 0)
            {
                rootNode.Text = ipHeader.SourceAddress.ToString() + "-" +
                    ipHeader.DestinationAddress.ToString();

                //adaugarea nodurilor la arbore
                treeView.Invoke(AddTreeNode, new object[] { rootNode });
            }
        }

        //constructorul unui nod IP
        private TreeNode MakeIPTreeNode(AntetIP ipHeader)
        {
            TreeNode ipNode = new TreeNode();

            ipNode.Text = "IP";
            ipNode.Nodes.Add("Versiune: " + ipHeader.Version);
            ipNode.Nodes.Add("Lungime header: " + ipHeader.HeaderLength);
            ipNode.Nodes.Add("Servicii diferentiate: " + ipHeader.DifferentiatedServices);
            ipNode.Nodes.Add("Lungimea totala: " + ipHeader.TotalLength);
            ipNode.Nodes.Add("Identificare: " + ipHeader.Identification);
            ipNode.Nodes.Add("Flag-uri: " + ipHeader.Flags);
            ipNode.Nodes.Add("Offset-ul fragmentarii: " + ipHeader.FragmentationOffset);
            ipNode.Nodes.Add("Time to live: " + ipHeader.TTL);
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:
                    ipNode.Nodes.Add("Protocol: " + "TCP");
                    break;
                case Protocol.UDP:
                    ipNode.Nodes.Add("Protocol: " + "UDP");
                    break;
                case Protocol.Unknown:
                    ipNode.Nodes.Add("Protocol: " + "Unknown");
                    break;
            }
            ipNode.Nodes.Add("CRC: " + ipHeader.Checksum);
            ipNode.Nodes.Add("Sursa: " + ipHeader.SourceAddress.ToString());
            ipNode.Nodes.Add("Destinatia: " + ipHeader.DestinationAddress.ToString());
            return ipNode;
        }

        //constructorul unui nod ICMP
        private TreeNode MakeICMPTreeNode(AntetICMP icmpHeader)
        {
            TreeNode icmpNode = new TreeNode();

            icmpNode.Text = "ICMP";
            icmpNode.Nodes.Add("Tip ICMP: " + icmpHeader.ICMPType);
            icmpNode.Nodes.Add("Tip cod: " + icmpHeader.CodeType);
            icmpNode.Nodes.Add("CRC: " + icmpHeader.Checksum);
            icmpNode.Nodes.Add("Mesaj: " + icmpHeader.Message());

            return icmpNode;
        }

        //constructorul unui nod TCP
        private TreeNode MakeTCPTreeNode(AntetTCP tcpHeader)
        {
            TreeNode tcpNode = new TreeNode();

            tcpNode.Text = "TCP";

            tcpNode.Nodes.Add("Portul sursei: " + tcpHeader.SourcePort);
            tcpNode.Nodes.Add("Portul destinatiei: " + tcpHeader.DestinationPort);
            tcpNode.Nodes.Add("Numarul secventei: " + tcpHeader.SequenceNumber);

            if (tcpHeader.AcknowledgementNumber != "")
                tcpNode.Nodes.Add("Numarul de confirmare: " + tcpHeader.AcknowledgementNumber);

            tcpNode.Nodes.Add("Lungimea header-ului: " + tcpHeader.HeaderLength);
            tcpNode.Nodes.Add("Flag-uri: " + tcpHeader.Flags);
            tcpNode.Nodes.Add("Dimensiunea ferestrei: " + tcpHeader.WindowSize);
            tcpNode.Nodes.Add("CRC: " + tcpHeader.Checksum);

            if (tcpHeader.UrgentPointer != "")
                tcpNode.Nodes.Add("Urgent Pointer: " + tcpHeader.UrgentPointer);

            return tcpNode;
        }

        //constructorul unui nod UDP
        private TreeNode MakeUDPTreeNode(AntetUDP udpHeader)
        {
            TreeNode udpNode = new TreeNode();

            udpNode.Text = "UDP";
            udpNode.Nodes.Add("Portul sursei: " + udpHeader.SourcePort);
            udpNode.Nodes.Add("Portul destinatiei: " + udpHeader.DestinationPort);
            udpNode.Nodes.Add("Lungime: " + udpHeader.Length);
            udpNode.Nodes.Add("CRC: " + udpHeader.Checksum);

            return udpNode;
        }

        //constructorul unui nod DNS
        private TreeNode MakeDNSTreeNode(byte[] byteData, int nLength)
        {
            AntetDNS dnsHeader = new AntetDNS(byteData, nLength);

            TreeNode dnsNode = new TreeNode();

            dnsNode.Text = "DNS";
            dnsNode.Nodes.Add("IDentificare: " + dnsHeader.Identification);
            dnsNode.Nodes.Add("Flaguri: " + dnsHeader.Flags);
            dnsNode.Nodes.Add("Intrebari: " + dnsHeader.TotalQuestions);
            dnsNode.Nodes.Add("Rasouns RR: " + dnsHeader.TotalAnswerRRs);
            dnsNode.Nodes.Add("Autoritate RR: " + dnsHeader.TotalAuthorityRRs);
            dnsNode.Nodes.Add("Additional RR: " + dnsHeader.TotalAdditionalRRs);

            return dnsNode;
        }

        private void OnTreeNode_Add(TreeNode node)
        {
            treeView.Nodes.Add(node);
        }

        private void OnSnifferForm_Load(object sender, EventArgs e)
        {
            string strIP = null;

            IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));
            if (HosyEntry.AddressList.Length > 0)
            {
                foreach (IPAddress ip in HosyEntry.AddressList)
                {
                    strIP = ip.ToString();
                    cmbInterfaces.Items.Add(strIP);
                }
            }
            for (int i = 0; i < checkedListBox.Items.Count; ++i)
            {
                checkedListBox.SetItemChecked(i, true);
            }
        }

        private void OnSnifferForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (stateFlag)
            {
                mySocket.Close();
            }
        }

        private void OnNouToolStripMenuItem_Click(object sender, EventArgs e)
        {
            treeView.Nodes.Clear();
        }

        private void OnIesiToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void OncheckedListBox_Changed(object sender, EventArgs e)
        {
            pachet ^= (byte)(1 << checkedListBox.SelectedIndex);
        }

    }
}