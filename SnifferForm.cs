using System;
using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;

namespace NetworkSniffer
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
        private readonly Action<TreeNode> AddTreeNode;

        //private delegate void AddTreeNode(TreeNode node);

        public SnifferForm()
        {
            InitializeComponent();
            AddTreeNode = new Action<TreeNode>(OnTreeNode_Add);
        }

        private void State(bool State)
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
                MessageBox.Show("Alegeti interfata pentru capturarea pachetelor.", "NetworkSniffer",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            try
            {
                if (!stateFlag)
                {
                    //incepe capturarea pachetelor

                    State(true);

                    mySocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

                    //leagam sochetul de adresa selectata
                    mySocket.Bind(new IPEndPoint(IPAddress.Parse(cmbInterfaces.Text), 0));

                    //setam optiunile socketului
                    mySocket.SetSocketOption(SocketOptionLevel.IP,              //doar pt pachete IP
                                               SocketOptionName.HeaderIncluded, //include header-ul
                                               true);                           //optiuni

                    byte[] inBytes = [1, 0, 0, 0];
                    byte[] outBytes = [1, 0, 0, 0]; //prinde pachetele ce ies

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
                    State(false);
                    //inchiderea socket-ului
                    mySocket.Close();
                }
            }
            catch (SocketException ex)
            {
                MessageBox.Show(ex.Message + "\n" + "Probleme legate de socket !", "NetworkSniffer",
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
                MessageBox.Show(se.Message + "\n" + "Probleme legate de receptie !", "NetworkSniffer",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ParseData(byte[] byteData, int nReceived)
        {
            TreeNode rootNode = new ();

            //Intru cit toate pachetele is de tip ip , 
            //scoatem header-ul si determinam tipul pachetului
            HeaderIP ipHeader = new (byteData, nReceived);

            if ((pachet & 1) == 1)
            {
                TreeNode ipNode = MakeIPTreeNode(ipHeader);
                rootNode.Nodes.Add(ipNode);
            }

            //acum analizam continutul 
            switch (ipHeader.Protocol)
            {
                case Protocol.ICMP:

                    HeaderICMP icmpHeader = new (ipHeader.Data,             //data continuta in pachetul IP
                                                        ipHeader.MessageLength);    //lungimea datei                    
                    if ((pachet & 2) == 2)
                    {
                        TreeNode icmpNode = MakeICMPTreeNode(icmpHeader);

                        rootNode.Nodes.Add(icmpNode);
                    }
                    break;

                case Protocol.TCP:

                    AntetTCP tcpHeader = new (ipHeader.Data,              //data continuta in pachetul IP
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
                        TreeNode dnsNode = MakeDNSTreeNode(tcpHeader.Data, (int)tcpHeader.DataLength);
                        rootNode.Nodes.Add(dnsNode);
                    }

                    break;

                case Protocol.UDP:

                    HeaderUDP udpHeader = new (ipHeader.Data,              //pachetul UDP continut de IP
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
                treeView.Invoke(AddTreeNode, [rootNode]);
            }
        }

        //constructorul unui nod IP
        private static TreeNode MakeIPTreeNode(HeaderIP ipHeader)
        {
            TreeNode ipNode = new()
            {
                Text = "IP"
            };
            ipNode.Nodes.Add("Version: " + ipHeader.Version);
            ipNode.Nodes.Add("Headre length: " + ipHeader.HeaderLength);
            ipNode.Nodes.Add("Type of services: " + ipHeader.TypeOfService);
            ipNode.Nodes.Add("Total length: " + ipHeader.TotalLength);
            ipNode.Nodes.Add("Identification: " + ipHeader.Identification);
            ipNode.Nodes.Add("ControlBits: " + ipHeader.Flags);
            ipNode.Nodes.Add("Fragment offset: " + ipHeader.FragmentOffset);
            ipNode.Nodes.Add("Time to live: " + ipHeader.TimeToLive);
            switch (ipHeader.Protocol)
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
            ipNode.Nodes.Add("Checksum: " + ipHeader.Checksum);
            ipNode.Nodes.Add("Source Address: " + ipHeader.SourceAddress.ToString());
            ipNode.Nodes.Add("Destination Address: " + ipHeader.DestinationAddress.ToString());
            return ipNode;
        }

        //constructorul unui nod ICMP
        private static TreeNode MakeICMPTreeNode(HeaderICMP icmpHeader)
        {
            TreeNode icmpNode = new()
            {
                Text = "ICMP"
            };
            icmpNode.Nodes.Add("Type: " + icmpHeader.Type);
            icmpNode.Nodes.Add("Code: " + icmpHeader.Code);
            icmpNode.Nodes.Add("Checksum: " + icmpHeader.Checksum);
            icmpNode.Nodes.Add("Data: " + icmpHeader.Message);

            return icmpNode;
        }

        //constructorul unui nod TCP
        private static TreeNode MakeTCPTreeNode(AntetTCP tcpHeader)
        {
            TreeNode tcpNode = new()
            {
                Text = "TCP"
            };
            tcpNode.Nodes.Add("Source port: " + tcpHeader.SourcePort);
            tcpNode.Nodes.Add("Destination port: " + tcpHeader.DestinationPort);
            tcpNode.Nodes.Add("Sequence number: " + tcpHeader.SequenceNumber);

            if (tcpHeader.AcknowledgementNumber != "")
                tcpNode.Nodes.Add("Acknowledgement number: " + tcpHeader.AcknowledgementNumber);

            tcpNode.Nodes.Add("Lungimea header-ului: " + tcpHeader.HeaderLength);
            tcpNode.Nodes.Add("Flag-uri: " + tcpHeader.ControlBits);
            tcpNode.Nodes.Add("Dimensiunea ferestrei: " + tcpHeader.Window);
            tcpNode.Nodes.Add("CRC: " + tcpHeader.Checksum);

            if (tcpHeader.UrgentPointer != "")
                tcpNode.Nodes.Add("Urgent Pointer: " + tcpHeader.UrgentPointer);

            return tcpNode;
        }

        //constructorul unui nod UDP
        private static TreeNode MakeUDPTreeNode(HeaderUDP udpHeader)
        {
            TreeNode udpNode = new()
            {
                Text = "UDP"
            };
            udpNode.Nodes.Add("Portul sursei: " + udpHeader.SourcePort);
            udpNode.Nodes.Add("Portul destinatiei: " + udpHeader.DestinationPort);
            udpNode.Nodes.Add("Lungime: " + udpHeader.Length);
            udpNode.Nodes.Add("CRC: " + udpHeader.Checksum);

            return udpNode;
        }

        /// <summary>
        /// DNS tree node constructor
        /// </summary>
        /// <param name="byteData"></param>
        /// <param name="nLength"></param>
        /// <returns></returns>
        private static TreeNode MakeDNSTreeNode(byte[] byteData, int nLength)
        {
            HeaderDNS dnsHeader = new (byteData, nLength);

            TreeNode dnsNode = new()
            {
                Text = "DNS"
            };
            dnsNode.Nodes.Add("Identifier: " + dnsHeader.Identifier);
            dnsNode.Nodes.Add("ControlBits: " + dnsHeader.Flags);
            dnsNode.Nodes.Add("Questions count: " + dnsHeader.QuestionsCount);
            dnsNode.Nodes.Add("Answers cound: " + dnsHeader.AnswersCount);
            dnsNode.Nodes.Add("Name servres count: " + dnsHeader.NameServersCount);
            dnsNode.Nodes.Add("Additional record count: " + dnsHeader.AdditionalRecordsCount);

            return dnsNode;
        }

        private void OnTreeNode_Add(TreeNode node)
        {
            treeView.Nodes.Add(node);
        }

        private void OnNetworkSnifferForm_Load(object sender, EventArgs e)
        {
            string strIP;

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

        private void OnNetworkSnifferForm_FormClosing(object sender, FormClosingEventArgs e)
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