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
        /// <summary>
        /// Socket that sniffes the packets
        /// </summary>
        private Socket mySocket;
        /// <summary>
        /// Receive buffer (65535 - max packet size)
        /// </summary>
        private byte[] dataBuffer = new byte[65535];
        private bool isRunning = false;
        private byte pachet = 15;
        private readonly Action<TreeNode> AddTreeNode;

        public SnifferForm()
        {
            InitializeComponent();
            AddTreeNode = new Action<TreeNode>(OnTreeNode_Add);
        }

        private bool IsRunning
        {
            set
            {
                if (value)
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
                isRunning = value;
            }
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
                if (!isRunning)
                {
                    // Start capturing
                    IsRunning = true;
                    // Create a socket
                    mySocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                    // Bind socket to the selected in terface IP
                    mySocket.Bind(new IPEndPoint(IPAddress.Parse(cmbInterfaces.Text), 0));
                    // Limit to IP packets and include the header
                    mySocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

                    // Option for incomming bytes
                    byte[] inBytes = [1, 0, 0, 0];
                    // Option for outcomming bytes
                    byte[] outBytes = [1, 0, 0, 0];

                    // Socket.IOControl is the alternative for WSAIoctl from Winsock 2
                    // IOControlCode.ReceiveAll is the equivalent for SIO_RCVALL from Winsock 2
                    mySocket.IOControl(IOControlCode.ReceiveAll, inBytes, outBytes);

                    // Receive packets asynchornuously
                    mySocket.BeginReceive(dataBuffer, 0, dataBuffer.Length, SocketFlags.None, new AsyncCallback(OnData_Receive), null);
                }
                else
                {
                    // Stop capturing
                    IsRunning = false;
                    // Close the socket
                    mySocket.Close();
                }
            }
            catch (SocketException ex)
            {
                MessageBox.Show(ex.Message, "NetworkSniffer Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

        }

        private void OnData_Receive(IAsyncResult ar)
        {
            try
            {
                int nReceived = mySocket.EndReceive(ar);

                // Parse the packet
                ParseData(dataBuffer, nReceived);

                if (isRunning)
                {
                    //dataBuffer = new byte[8192];
                    // Continue capturing
                    mySocket.BeginReceive(dataBuffer, 0, dataBuffer.Length, SocketFlags.None, new AsyncCallback(OnData_Receive), null);
                }
            }
            catch (ObjectDisposedException)
            {
            }
            catch (SocketException se)
            {
                MessageBox.Show(se.Message, "NetworkSniffer Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ParseData(byte[] byteData, int nReceived)
        {
            TreeNode rootNode = new ();

            // Parse the IP packet and extract next level protocol packet
            HeaderIP ipHeader = new (byteData, nReceived);

            if ((pachet & 1) == 1)
            {
                TreeNode ipNode = MakeIPTreeNode(ipHeader);
                rootNode.Nodes.Add(ipNode);
            }

            if (ipHeader.Data != null)
            {
                // Parse next level protocol packet and parse the header
                switch (ipHeader.Protocol)
                {
                    case Protocol.ICMP:

                        HeaderICMP icmpHeader = new(ipHeader.Data, ipHeader.MessageLength);
                        if ((pachet & 2) == 2)
                        {
                            TreeNode icmpNode = MakeICMPTreeNode(icmpHeader);
                            rootNode.Nodes.Add(icmpNode);
                        }
                        break;

                    case Protocol.TCP:

                        AntetTCP tcpHeader = new(ipHeader.Data, ipHeader.MessageLength);
                        if ((pachet & 4) == 4)
                        {
                            TreeNode tcpNode = MakeTCPTreeNode(tcpHeader);
                            rootNode.Nodes.Add(tcpNode);
                        }
                        // If port number is 53, next level protocol is DNS (DNS can be both TCP and UDP)
                        if ((tcpHeader.DestinationPort == "53" || tcpHeader.SourcePort == "53") && (pachet & 16) == 16)
                        {
                            TreeNode dnsNode = MakeDNSTreeNode(tcpHeader.Data, tcpHeader.DataLength);
                            rootNode.Nodes.Add(dnsNode);
                        }

                        break;

                    case Protocol.UDP:

                        HeaderUDP udpHeader = new(ipHeader.Data, ipHeader.MessageLength);
                        if ((pachet & 8) == 8)
                        {
                            TreeNode udpNode = MakeUDPTreeNode(udpHeader);
                            rootNode.Nodes.Add(udpNode);
                        }
                        // If port number is 53, next level protocol is DNS (DNS can be both TCP and UDP)
                        if ((udpHeader.DestinationPort == "53" || udpHeader.SourcePort == "53") && (pachet & 16) == 16)
                        {
                            TreeNode dnsNode = MakeDNSTreeNode(udpHeader.Data, Convert.ToInt32(udpHeader.Length) - 8);
                            rootNode.Nodes.Add(dnsNode);
                        }

                        break;

                    case Protocol.Unknown:
                        break;
                }
            }

            if (rootNode.Nodes.Count != 0)
            {
                rootNode.Text = ipHeader.SourceAddress.ToString() + "-" + ipHeader.DestinationAddress.ToString();
                // Add node to the tree
                treeView.Invoke(AddTreeNode, [rootNode]);
            }
        }

        // IP tree node builder
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

        // ICMP tree node builder
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

        // TCP tree node builder
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

        // UDP tree node builder
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
            if (isRunning)
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