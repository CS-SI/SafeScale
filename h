SSH(1)                                BSD General Commands Manual                                SSH(1)

NNAAMMEE
     sssshh — OpenSSH SSH client (remote login program)

SSYYNNOOPPSSIISS
     sssshh [--4466AAaaCCffGGggKKkkMMNNnnqqssTTttVVvvXXxxYYyy] [--bb _b_i_n_d___a_d_d_r_e_s_s] [--cc _c_i_p_h_e_r___s_p_e_c] [--DD [_b_i_n_d___a_d_d_r_e_s_s:]_p_o_r_t]
         [--EE _l_o_g___f_i_l_e] [--ee _e_s_c_a_p_e___c_h_a_r] [--FF _c_o_n_f_i_g_f_i_l_e] [--II _p_k_c_s_1_1] [--ii _i_d_e_n_t_i_t_y___f_i_l_e]
         [--JJ [_u_s_e_r@]_h_o_s_t[:_p_o_r_t]] [--LL _a_d_d_r_e_s_s] [--ll _l_o_g_i_n___n_a_m_e] [--mm _m_a_c___s_p_e_c] [--OO _c_t_l___c_m_d] [--oo _o_p_t_i_o_n]
         [--pp _p_o_r_t] [--QQ _q_u_e_r_y___o_p_t_i_o_n] [--RR _a_d_d_r_e_s_s] [--SS _c_t_l___p_a_t_h] [--WW _h_o_s_t:_p_o_r_t]
         [--ww _l_o_c_a_l___t_u_n[:_r_e_m_o_t_e___t_u_n]] [_u_s_e_r@]_h_o_s_t_n_a_m_e [_c_o_m_m_a_n_d]

DDEESSCCRRIIPPTTIIOONN
     sssshh (SSH client) is a program for logging into a remote machine and for executing commands on a
     remote machine.  It is intended to provide secure encrypted communications between two untrusted
     hosts over an insecure network.  X11 connections, arbitrary TCP ports and UNIX-domain sockets can
     also be forwarded over the secure channel.

     sssshh connects and logs into the specified _h_o_s_t_n_a_m_e (with optional _u_s_e_r name).  The user must prove
     his/her identity to the remote machine using one of several methods (see below).

     If _c_o_m_m_a_n_d is specified, it is executed on the remote host instead of a login shell.

     The options are as follows:

     --44      Forces sssshh to use IPv4 addresses only.

     --66      Forces sssshh to use IPv6 addresses only.

     --AA      Enables forwarding of the authentication agent connection.  This can also be specified on
             a per-host basis in a configuration file.

             Agent forwarding should be enabled with caution.  Users with the ability to bypass file
             permissions on the remote host (for the agent's UNIX-domain socket) can access the local
             agent through the forwarded connection.  An attacker cannot obtain key material from the
             agent, however they can perform operations on the keys that enable them to authenticate
             using the identities loaded into the agent.

     --aa      Disables forwarding of the authentication agent connection.

     --bb _b_i_n_d___a_d_d_r_e_s_s
             Use _b_i_n_d___a_d_d_r_e_s_s on the local machine as the source address of the connection.  Only use‐
             ful on systems with more than one address.

     --CC      Requests compression of all data (including stdin, stdout, stderr, and data for forwarded
             X11, TCP and UNIX-domain connections).  The compression algorithm is the same used by
             gzip(1).  Compression is desirable on modem lines and other slow connections, but will
             only slow down things on fast networks.  The default value can be set on a host-by-host
             basis in the configuration files; see the CCoommpprreessssiioonn option.

     --cc _c_i_p_h_e_r___s_p_e_c
             Selects the cipher specification for encrypting the session.  _c_i_p_h_e_r___s_p_e_c is a comma-sepa‐
             rated list of ciphers listed in order of preference.  See the CCiipphheerrss keyword in
             ssh_config(5) for more information.

     --DD [_b_i_n_d___a_d_d_r_e_s_s:]_p_o_r_t
             Specifies a local “dynamic” application-level port forwarding.  This works by allocating a
             socket to listen to _p_o_r_t on the local side, optionally bound to the specified
             _b_i_n_d___a_d_d_r_e_s_s.  Whenever a connection is made to this port, the connection is forwarded
             over the secure channel, and the application protocol is then used to determine where to
             connect to from the remote machine.  Currently the SOCKS4 and SOCKS5 protocols are sup‐
             ported, and sssshh will act as a SOCKS server.  Only root can forward privileged ports.
             Dynamic port forwardings can also be specified in the configuration file.

             IPv6 addresses can be specified by enclosing the address in square brackets.  Only the
             superuser can forward privileged ports.  By default, the local port is bound in accordance
             with the GGaatteewwaayyPPoorrttss setting.  However, an explicit _b_i_n_d___a_d_d_r_e_s_s may be used to bind the
             connection to a specific address.  The _b_i_n_d___a_d_d_r_e_s_s of “localhost” indicates that the lis‐
             tening port be bound for local use only, while an empty address or ‘*’ indicates that the
             port should be available from all interfaces.

     --EE _l_o_g___f_i_l_e
             Append debug logs to _l_o_g___f_i_l_e instead of standard error.

     --ee _e_s_c_a_p_e___c_h_a_r
             Sets the escape character for sessions with a pty (default: ‘~’).  The escape character is
             only recognized at the beginning of a line.  The escape character followed by a dot (‘.’)
             closes the connection; followed by control-Z suspends the connection; and followed by
             itself sends the escape character once.  Setting the character to “none” disables any
             escapes and makes the session fully transparent.

     --FF _c_o_n_f_i_g_f_i_l_e
             Specifies an alternative per-user configuration file.  If a configuration file is given on
             the command line, the system-wide configuration file (_/_e_t_c_/_s_s_h_/_s_s_h___c_o_n_f_i_g) will be
             ignored.  The default for the per-user configuration file is _~_/_._s_s_h_/_c_o_n_f_i_g.

     --ff      Requests sssshh to go to background just before command execution.  This is useful if sssshh is
             going to ask for passwords or passphrases, but the user wants it in the background.  This
             implies --nn.  The recommended way to start X11 programs at a remote site is with something
             like sssshh --ff hhoosstt xxtteerrmm.

             If the EExxiittOOnnFFoorrwwaarrddFFaaiilluurree configuration option is set to “yes”, then a client started
             with --ff will wait for all remote port forwards to be successfully established before plac‐
             ing itself in the background.

     --GG      Causes sssshh to print its configuration after evaluating HHoosstt and MMaattcchh blocks and exit.

     --gg      Allows remote hosts to connect to local forwarded ports.  If used on a multiplexed connec‐
             tion, then this option must be specified on the master process.

     --II _p_k_c_s_1_1
             Specify the PKCS#11 shared library sssshh should use to communicate with a PKCS#11 token pro‐
             viding the user's private RSA key.

     --ii _i_d_e_n_t_i_t_y___f_i_l_e
             Selects a file from which the identity (private key) for public key authentication is
             read.  The default is _~_/_._s_s_h_/_i_d___d_s_a, _~_/_._s_s_h_/_i_d___e_c_d_s_a, _~_/_._s_s_h_/_i_d___e_d_2_5_5_1_9 and _~_/_._s_s_h_/_i_d___r_s_a.
             Identity files may also be specified on a per-host basis in the configuration file.  It is
             possible to have multiple --ii options (and multiple identities specified in configuration
             files).  If no certificates have been explicitly specified by the CCeerrttiiffiiccaatteeFFiillee direc‐
             tive, sssshh will also try to load certificate information from the filename obtained by
             appending _-_c_e_r_t_._p_u_b to identity filenames.

     --JJ [_u_s_e_r@]_h_o_s_t[:_p_o_r_t]
             Connect to the target host by first making a sssshh connection to the jump _h_o_s_t and then
             establishing a TCP forwarding to the ultimate destination from there.  Multiple jump hops
             may be specified separated by comma characters.  This is a shortcut to specify a PPrrooxxyyJJuummpp
             configuration directive.

     --KK      Enables GSSAPI-based authentication and forwarding (delegation) of GSSAPI credentials to
             the server.

     --kk      Disables forwarding (delegation) of GSSAPI credentials to the server.

     --LL [_b_i_n_d___a_d_d_r_e_s_s:]_p_o_r_t:_h_o_s_t:_h_o_s_t_p_o_r_t
     --LL [_b_i_n_d___a_d_d_r_e_s_s:]_p_o_r_t:_r_e_m_o_t_e___s_o_c_k_e_t
     --LL _l_o_c_a_l___s_o_c_k_e_t:_h_o_s_t:_h_o_s_t_p_o_r_t
     --LL _l_o_c_a_l___s_o_c_k_e_t:_r_e_m_o_t_e___s_o_c_k_e_t
             Specifies that connections to the given TCP port or Unix socket on the local (client) host
             are to be forwarded to the given host and port, or Unix socket, on the remote side.  This
             works by allocating a socket to listen to either a TCP _p_o_r_t on the local side, optionally
             bound to the specified _b_i_n_d___a_d_d_r_e_s_s, or to a Unix socket.  Whenever a connection is made
             to the local port or socket, the connection is forwarded over the secure channel, and a
             connection is made to either _h_o_s_t port _h_o_s_t_p_o_r_t, or the Unix socket _r_e_m_o_t_e___s_o_c_k_e_t, from
             the remote machine.

             Port forwardings can also be specified in the configuration file.  Only the superuser can
             forward privileged ports.  IPv6 addresses can be specified by enclosing the address in
             square brackets.

             By default, the local port is bound in accordance with the GGaatteewwaayyPPoorrttss setting.  However,
             an explicit _b_i_n_d___a_d_d_r_e_s_s may be used to bind the connection to a specific address.  The
             _b_i_n_d___a_d_d_r_e_s_s of “localhost” indicates that the listening port be bound for local use only,
             while an empty address or ‘*’ indicates that the port should be available from all inter‐
             faces.

     --ll _l_o_g_i_n___n_a_m_e
             Specifies the user to log in as on the remote machine.  This also may be specified on a
             per-host basis in the configuration file.

     --MM      Places the sssshh client into “master” mode for connection sharing.  Multiple --MM options
             places sssshh into “master” mode with confirmation required before slave connections are
             accepted.  Refer to the description of CCoonnttrroollMMaasstteerr in ssh_config(5) for details.

     --mm _m_a_c___s_p_e_c
             A comma-separated list of MAC (message authentication code) algorithms, specified in order
             of preference.  See the MMAACCss keyword for more information.

     --NN      Do not execute a remote command.  This is useful for just forwarding ports.

     --nn      Redirects stdin from _/_d_e_v_/_n_u_l_l (actually, prevents reading from stdin).  This must be used
             when sssshh is run in the background.  A common trick is to use this to run X11 programs on a
             remote machine.  For example, sssshh --nn sshhaaddoowwss..ccss..hhuutt..ffii eemmaaccss && will start an emacs on
             shadows.cs.hut.fi, and the X11 connection will be automatically forwarded over an
             encrypted channel.  The sssshh program will be put in the background.  (This does not work if
             sssshh needs to ask for a password or passphrase; see also the --ff option.)

     --OO _c_t_l___c_m_d
             Control an active connection multiplexing master process.  When the --OO option is speci‐
             fied, the _c_t_l___c_m_d argument is interpreted and passed to the master process.  Valid com‐
             mands are: “check” (check that the master process is running), “forward” (request forward‐
             ings without command execution), “cancel” (cancel forwardings), “exit” (request the master
             to exit), and “stop” (request the master to stop accepting further multiplexing requests).

     --oo _o_p_t_i_o_n
             Can be used to give options in the format used in the configuration file.  This is useful
             for specifying options for which there is no separate command-line flag.  For full details
             of the options listed below, and their possible values, see ssh_config(5).

                   AddKeysToAgent
                   AddressFamily
                   BatchMode
                   BindAddress
                   CanonicalDomains
                   CanonicalizeFallbackLocal
                   CanonicalizeHostname
                   CanonicalizeMaxDots
                   CanonicalizePermittedCNAMEs
                   CertificateFile
                   ChallengeResponseAuthentication
                   CheckHostIP
                   Ciphers
                   ClearAllForwardings
                   Compression
                   ConnectionAttempts
                   ConnectTimeout
                   ControlMaster
                   ControlPath
                   ControlPersist
                   DynamicForward
                   EscapeChar
                   ExitOnForwardFailure
                   FingerprintHash
                   ForwardAgent
                   ForwardX11
                   ForwardX11Timeout
                   ForwardX11Trusted
                   GatewayPorts
                   GlobalKnownHostsFile
                   GSSAPIAuthentication
                   GSSAPIDelegateCredentials
                   HashKnownHosts
                   Host
                   HostbasedAuthentication
                   HostbasedKeyTypes
                   HostKeyAlgorithms
                   HostKeyAlias
                   HostName
                   IdentitiesOnly
                   IdentityAgent
                   IdentityFile
                   Include
                   IPQoS
                   KbdInteractiveAuthentication
                   KbdInteractiveDevices
                   KexAlgorithms
                   LocalCommand
                   LocalForward
                   LogLevel
                   MACs
                   Match
                   NoHostAuthenticationForLocalhost
                   NumberOfPasswordPrompts
                   PasswordAuthentication
                   PermitLocalCommand
                   PKCS11Provider
                   Port
                   PreferredAuthentications
                   ProxyCommand
                   ProxyJump
                   ProxyUseFdpass
                   PubkeyAcceptedKeyTypes
                   PubkeyAuthentication
                   RekeyLimit
                   RemoteCommand
                   RemoteForward
                   RequestTTY
                   SendEnv
                   ServerAliveInterval
                   ServerAliveCountMax
                   StreamLocalBindMask
                   StreamLocalBindUnlink
                   StrictHostKeyChecking
                   TCPKeepAlive
                   Tunnel
                   TunnelDevice
                   UpdateHostKeys
                   UsePrivilegedPort
                   User
                   UserKnownHostsFile
                   VerifyHostKeyDNS
                   VisualHostKey
                   XAuthLocation

     --pp _p_o_r_t
             Port to connect to on the remote host.  This can be specified on a per-host basis in the
             configuration file.

     --QQ _q_u_e_r_y___o_p_t_i_o_n
             Queries sssshh for the algorithms supported for the specified version 2.  The available fea‐
             tures are: _c_i_p_h_e_r (supported symmetric ciphers), _c_i_p_h_e_r_-_a_u_t_h (supported symmetric ciphers
             that support authenticated encryption), _m_a_c (supported message integrity codes), _k_e_x (key
             exchange algorithms), _k_e_y (key types), _k_e_y_-_c_e_r_t (certificate key types), _k_e_y_-_p_l_a_i_n (non-
             certificate key types), and _p_r_o_t_o_c_o_l_-_v_e_r_s_i_o_n (supported SSH protocol versions).

     --qq      Quiet mode.  Causes most warning and diagnostic messages to be suppressed.

     --RR [_b_i_n_d___a_d_d_r_e_s_s:]_p_o_r_t:_h_o_s_t:_h_o_s_t_p_o_r_t
     --RR [_b_i_n_d___a_d_d_r_e_s_s:]_p_o_r_t:_l_o_c_a_l___s_o_c_k_e_t
     --RR _r_e_m_o_t_e___s_o_c_k_e_t:_h_o_s_t:_h_o_s_t_p_o_r_t
     --RR _r_e_m_o_t_e___s_o_c_k_e_t:_l_o_c_a_l___s_o_c_k_e_t
     --RR [_b_i_n_d___a_d_d_r_e_s_s:]_p_o_r_t
             Specifies that connections to the given TCP port or Unix socket on the remote (server)
             host are to be forwarded to the local side.

             This works by allocating a socket to listen to either a TCP _p_o_r_t or to a Unix socket on
             the remote side.  Whenever a connection is made to this port or Unix socket, the connec‐
             tion is forwarded over the secure channel, and a connection is made from the local machine
             to either an explicit destination specified by _h_o_s_t port _h_o_s_t_p_o_r_t, or _l_o_c_a_l___s_o_c_k_e_t, or, if
             no explicit destination was specified, sssshh will act as a SOCKS 4/5 proxy and forward con‐
             nections to the destinations requested by the remote SOCKS client.

             Port forwardings can also be specified in the configuration file.  Privileged ports can be
             forwarded only when logging in as root on the remote machine.  IPv6 addresses can be spec‐
             ified by enclosing the address in square brackets.

             By default, TCP listening sockets on the server will be bound to the loopback interface
             only.  This may be overridden by specifying a _b_i_n_d___a_d_d_r_e_s_s.  An empty _b_i_n_d___a_d_d_r_e_s_s, or the
             address ‘*’, indicates that the remote socket should listen on all interfaces.  Specifying
             a remote _b_i_n_d___a_d_d_r_e_s_s will only succeed if the server's GGaatteewwaayyPPoorrttss option is enabled
             (see sshd_config(5)).

             If the _p_o_r_t argument is ‘0’, the listen port will be dynamically allocated on the server
             and reported to the client at run time.  When used together with --OO ffoorrwwaarrdd the allocated
             port will be printed to the standard output.

     --SS _c_t_l___p_a_t_h
             Specifies the location of a control socket for connection sharing, or the string “none” to
             disable connection sharing.  Refer to the description of CCoonnttrroollPPaatthh and CCoonnttrroollMMaasstteerr in
             ssh_config(5) for details.

     --ss      May be used to request invocation of a subsystem on the remote system.  Subsystems facili‐
             tate the use of SSH as a secure transport for other applications (e.g. sftp(1)).  The sub‐
             system is specified as the remote command.

     --TT      Disable pseudo-terminal allocation.

     --tt      Force pseudo-terminal allocation.  This can be used to execute arbitrary screen-based pro‐
             grams on a remote machine, which can be very useful, e.g. when implementing menu services.
             Multiple --tt options force tty allocation, even if sssshh has no local tty.

     --VV      Display the version number and exit.

     --vv      Verbose mode.  Causes sssshh to print debugging messages about its progress.  This is helpful
             in debugging connection, authentication, and configuration problems.  Multiple --vv options
             increase the verbosity.  The maximum is 3.

     --WW _h_o_s_t:_p_o_r_t
             Requests that standard input and output on the client be forwarded to _h_o_s_t on _p_o_r_t over
             the secure channel.  Implies --NN, --TT, EExxiittOOnnFFoorrwwaarrddFFaaiilluurree and CClleeaarrAAllllFFoorrwwaarrddiinnggss, though
             these can be overridden in the configuration file or using --oo command line options.

     --ww _l_o_c_a_l___t_u_n[:_r_e_m_o_t_e___t_u_n]
             Requests tunnel device forwarding with the specified tun(4) devices between the client
             (_l_o_c_a_l___t_u_n) and the server (_r_e_m_o_t_e___t_u_n).

             The devices may be specified by numerical ID or the keyword “any”, which uses the next
             available tunnel device.  If _r_e_m_o_t_e___t_u_n is not specified, it defaults to “any”.  See also
             the TTuunnnneell and TTuunnnneellDDeevviiccee directives in ssh_config(5).  If the TTuunnnneell directive is
             unset, it is set to the default tunnel mode, which is “point-to-point”.

     --XX      Enables X11 forwarding.  This can also be specified on a per-host basis in a configuration
             file.

             X11 forwarding should be enabled with caution.  Users with the ability to bypass file per‐
             missions on the remote host (for the user's X authorization database) can access the local
             X11 display through the forwarded connection.  An attacker may then be able to perform
             activities such as keystroke monitoring.

             For this reason, X11 forwarding is subjected to X11 SECURITY extension restrictions by
             default.  Please refer to the sssshh --YY option and the FFoorrwwaarrddXX1111TTrruusstteedd directive in
             ssh_config(5) for more information.

             (Debian-specific: X11 forwarding is not subjected to X11 SECURITY extension restrictions
             by default, because too many programs currently crash in this mode.  Set the
             FFoorrwwaarrddXX1111TTrruusstteedd option to “no” to restore the upstream behaviour.  This may change in
             future depending on client-side improvements.)

     --xx      Disables X11 forwarding.

     --YY      Enables trusted X11 forwarding.  Trusted X11 forwardings are not subjected to the X11
             SECURITY extension controls.

             (Debian-specific: This option does nothing in the default configuration: it is equivalent
             to “FFoorrwwaarrddXX1111TTrruusstteedd yes”, which is the default as described above.  Set the
             FFoorrwwaarrddXX1111TTrruusstteedd option to “no” to restore the upstream behaviour.  This may change in
             future depending on client-side improvements.)

     --yy      Send log information using the syslog(3) system module.  By default this information is
             sent to stderr.

     sssshh may additionally obtain configuration data from a per-user configuration file and a system-
     wide configuration file.  The file format and configuration options are described in
     ssh_config(5).

AAUUTTHHEENNTTIICCAATTIIOONN
     The OpenSSH SSH client supports SSH protocol 2.

     The methods available for authentication are: GSSAPI-based authentication, host-based authentica‐
     tion, public key authentication, challenge-response authentication, and password authentication.
     Authentication methods are tried in the order specified above, though PPrreeffeerrrreeddAAuutthheennttiiccaattiioonnss can
     be used to change the default order.

     Host-based authentication works as follows: If the machine the user logs in from is listed in
     _/_e_t_c_/_h_o_s_t_s_._e_q_u_i_v or _/_e_t_c_/_s_s_h_/_s_h_o_s_t_s_._e_q_u_i_v on the remote machine, and the user names are the same
     on both sides, or if the files _~_/_._r_h_o_s_t_s or _~_/_._s_h_o_s_t_s exist in the user's home directory on the
     remote machine and contain a line containing the name of the client machine and the name of the
     user on that machine, the user is considered for login.  Additionally, the server _m_u_s_t be able to
     verify the client's host key (see the description of _/_e_t_c_/_s_s_h_/_s_s_h___k_n_o_w_n___h_o_s_t_s and
     _~_/_._s_s_h_/_k_n_o_w_n___h_o_s_t_s, below) for login to be permitted.  This authentication method closes security
     holes due to IP spoofing, DNS spoofing, and routing spoofing.  [Note to the administrator:
     _/_e_t_c_/_h_o_s_t_s_._e_q_u_i_v, _~_/_._r_h_o_s_t_s, and the rlogin/rsh protocol in general, are inherently insecure and
     should be disabled if security is desired.]

     Public key authentication works as follows: The scheme is based on public-key cryptography, using
     cryptosystems where encryption and decryption are done using separate keys, and it is unfeasible
     to derive the decryption key from the encryption key.  The idea is that each user creates a pub‐
     lic/private key pair for authentication purposes.  The server knows the public key, and only the
     user knows the private key.  sssshh implements public key authentication protocol automatically,
     using one of the DSA, ECDSA, Ed25519 or RSA algorithms.  The HISTORY section of ssl(8) (on non-
     OpenBSD systems, see http://www.openbsd.org/cgi-bin/man.cgi?query=ssl&sektion=8#HISTORY) contains
     a brief discussion of the DSA and RSA algorithms.

     The file _~_/_._s_s_h_/_a_u_t_h_o_r_i_z_e_d___k_e_y_s lists the public keys that are permitted for logging in.  When the
     user logs in, the sssshh program tells the server which key pair it would like to use for authentica‐
     tion.  The client proves that it has access to the private key and the server checks that the cor‐
     responding public key is authorized to accept the account.

     The server may inform the client of errors that prevented public key authentication from succeed‐
     ing after authentication completes using a different method.  These may be viewed by increasing
     the LLooggLLeevveell to DDEEBBUUGG or higher (e.g. by using the --vv flag).

     The user creates his/her key pair by running ssh-keygen(1).  This stores the private key in
     _~_/_._s_s_h_/_i_d___d_s_a (DSA), _~_/_._s_s_h_/_i_d___e_c_d_s_a (ECDSA), _~_/_._s_s_h_/_i_d___e_d_2_5_5_1_9 (Ed25519), or _~_/_._s_s_h_/_i_d___r_s_a (RSA)
     and stores the public key in _~_/_._s_s_h_/_i_d___d_s_a_._p_u_b (DSA), _~_/_._s_s_h_/_i_d___e_c_d_s_a_._p_u_b (ECDSA),
     _~_/_._s_s_h_/_i_d___e_d_2_5_5_1_9_._p_u_b (Ed25519), or _~_/_._s_s_h_/_i_d___r_s_a_._p_u_b (RSA) in the user's home directory.  The
     user should then copy the public key to _~_/_._s_s_h_/_a_u_t_h_o_r_i_z_e_d___k_e_y_s in his/her home directory on the
     remote machine.  The _a_u_t_h_o_r_i_z_e_d___k_e_y_s file corresponds to the conventional _~_/_._r_h_o_s_t_s file, and has
     one key per line, though the lines can be very long.  After this, the user can log in without giv‐
     ing the password.

     A variation on public key authentication is available in the form of certificate authentication:
     instead of a set of public/private keys, signed certificates are used.  This has the advantage
     that a single trusted certification authority can be used in place of many public/private keys.
     See the CERTIFICATES section of ssh-keygen(1) for more information.

     The most convenient way to use public key or certificate authentication may be with an authentica‐
     tion agent.  See ssh-agent(1) and (optionally) the AAddddKKeeyyssTTooAAggeenntt directive in ssh_config(5) for
     more information.

     Challenge-response authentication works as follows: The server sends an arbitrary "challenge"
     text, and prompts for a response.  Examples of challenge-response authentication include BSD
     Authentication (see login.conf(5)) and PAM (some non-OpenBSD systems).

     Finally, if other authentication methods fail, sssshh prompts the user for a password.  The password
     is sent to the remote host for checking; however, since all communications are encrypted, the
     password cannot be seen by someone listening on the network.

     sssshh automatically maintains and checks a database containing identification for all hosts it has
     ever been used with.  Host keys are stored in _~_/_._s_s_h_/_k_n_o_w_n___h_o_s_t_s in the user's home directory.
     Additionally, the file _/_e_t_c_/_s_s_h_/_s_s_h___k_n_o_w_n___h_o_s_t_s is automatically checked for known hosts.  Any new
     hosts are automatically added to the user's file.  If a host's identification ever changes, sssshh
     warns about this and disables password authentication to prevent server spoofing or man-in-the-
     middle attacks, which could otherwise be used to circumvent the encryption.  The
     SSttrriiccttHHoossttKKeeyyCChheecckkiinngg option can be used to control logins to machines whose host key is not known
     or has changed.

     When the user's identity has been accepted by the server, the server either executes the given
     command in a non-interactive session or, if no command has been specified, logs into the machine
     and gives the user a normal shell as an interactive session.  All communication with the remote
     command or shell will be automatically encrypted.

     If an interactive session is requested sssshh by default will only request a pseudo-terminal (pty)
     for interactive sessions when the client has one.  The flags --TT and --tt can be used to override
     this behaviour.

     If a pseudo-terminal has been allocated the user may use the escape characters noted below.

     If no pseudo-terminal has been allocated, the session is transparent and can be used to reliably
     transfer binary data.  On most systems, setting the escape character to “none” will also make the
     session transparent even if a tty is used.

     The session terminates when the command or shell on the remote machine exits and all X11 and TCP
     connections have been closed.

EESSCCAAPPEE CCHHAARRAACCTTEERRSS
     When a pseudo-terminal has been requested, sssshh supports a number of functions through the use of
     an escape character.

     A single tilde character can be sent as ~~~~ or by following the tilde by a character other than
     those described below.  The escape character must always follow a newline to be interpreted as
     special.  The escape character can be changed in configuration files using the EEssccaappeeCChhaarr configu‐
     ration directive or on the command line by the --ee option.

     The supported escapes (assuming the default ‘~’) are:

     ~~..      Disconnect.

     ~~^^ZZ     Background sssshh.

     ~~##      List forwarded connections.

     ~~&&      Background sssshh at logout when waiting for forwarded connection / X11 sessions to termi‐
             nate.

     ~~??      Display a list of escape characters.

     ~~BB      Send a BREAK to the remote system (only useful if the peer supports it).

     ~~CC      Open command line.  Currently this allows the addition of port forwardings using the --LL,
             --RR and --DD options (see above).  It also allows the cancellation of existing port-forward‐
             ings with --KKLL[_b_i_n_d___a_d_d_r_e_s_s:]_p_o_r_t for local, --KKRR[_b_i_n_d___a_d_d_r_e_s_s:]_p_o_r_t for remote and
             --KKDD[_b_i_n_d___a_d_d_r_e_s_s:]_p_o_r_t for dynamic port-forwardings.  !!_c_o_m_m_a_n_d allows the user to execute
             a local command if the PPeerrmmiittLLooccaallCCoommmmaanndd option is enabled in ssh_config(5).  Basic help
             is available, using the --hh option.

     ~~RR      Request rekeying of the connection (only useful if the peer supports it).

     ~~VV      Decrease the verbosity (LLooggLLeevveell) when errors are being written to stderr.

     ~~vv      Increase the verbosity (LLooggLLeevveell) when errors are being written to stderr.

TTCCPP FFOORRWWAARRDDIINNGG
     Forwarding of arbitrary TCP connections over the secure channel can be specified either on the
     command line or in a configuration file.  One possible application of TCP forwarding is a secure
     connection to a mail server; another is going through firewalls.

     In the example below, we look at encrypting communication between an IRC client and server, even
     though the IRC server does not directly support encrypted communications.  This works as follows:
     the user connects to the remote host using sssshh, specifying a port to be used to forward connec‐
     tions to the remote server.  After that it is possible to start the service which is to be
     encrypted on the client machine, connecting to the same local port, and sssshh will encrypt and for‐
     ward the connection.

     The following example tunnels an IRC session from client machine “127.0.0.1” (localhost) to remote
     server “server.example.com”:

         $ ssh -f -L 1234:localhost:6667 server.example.com sleep 10
         $ irc -c '#users' -p 1234 pinky 127.0.0.1

     This tunnels a connection to IRC server “server.example.com”, joining channel “#users”, nickname
     “pinky”, using port 1234.  It doesn't matter which port is used, as long as it's greater than 1023
     (remember, only root can open sockets on privileged ports) and doesn't conflict with any ports
     already in use.  The connection is forwarded to port 6667 on the remote server, since that's the
     standard port for IRC services.

     The --ff option backgrounds sssshh and the remote command “sleep 10” is specified to allow an amount of
     time (10 seconds, in the example) to start the service which is to be tunnelled.  If no connec‐
     tions are made within the time specified, sssshh will exit.

XX1111 FFOORRWWAARRDDIINNGG
     If the FFoorrwwaarrddXX1111 variable is set to “yes” (or see the description of the --XX, --xx, and --YY options
     above) and the user is using X11 (the DISPLAY environment variable is set), the connection to the
     X11 display is automatically forwarded to the remote side in such a way that any X11 programs
     started from the shell (or command) will go through the encrypted channel, and the connection to
     the real X server will be made from the local machine.  The user should not manually set DISPLAY.
     Forwarding of X11 connections can be configured on the command line or in configuration files.

     The DISPLAY value set by sssshh will point to the server machine, but with a display number greater
     than zero.  This is normal, and happens because sssshh creates a “proxy” X server on the server
     machine for forwarding the connections over the encrypted channel.

     sssshh will also automatically set up Xauthority data on the server machine.  For this purpose, it
     will generate a random authorization cookie, store it in Xauthority on the server, and verify that
     any forwarded connections carry this cookie and replace it by the real cookie when the connection
     is opened.  The real authentication cookie is never sent to the server machine (and no cookies are
     sent in the plain).

     If the FFoorrwwaarrddAAggeenntt variable is set to “yes” (or see the description of the --AA and --aa options
     above) and the user is using an authentication agent, the connection to the agent is automatically
     forwarded to the remote side.

VVEERRIIFFYYIINNGG HHOOSSTT KKEEYYSS
     When connecting to a server for the first time, a fingerprint of the server's public key is pre‐
     sented to the user (unless the option SSttrriiccttHHoossttKKeeyyCChheecckkiinngg has been disabled).  Fingerprints can
     be determined using ssh-keygen(1):

           $ ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key

     If the fingerprint is already known, it can be matched and the key can be accepted or rejected.
     If only legacy (MD5) fingerprints for the server are available, the ssh-keygen(1) --EE option may be
     used to downgrade the fingerprint algorithm to match.

     Because of the difficulty of comparing host keys just by looking at fingerprint strings, there is
     also support to compare host keys visually, using _r_a_n_d_o_m _a_r_t.  By setting the VViissuuaallHHoossttKKeeyy option
     to “yes”, a small ASCII graphic gets displayed on every login to a server, no matter if the ses‐
     sion itself is interactive or not.  By learning the pattern a known server produces, a user can
     easily find out that the host key has changed when a completely different pattern is displayed.
     Because these patterns are not unambiguous however, a pattern that looks similar to the pattern
     remembered only gives a good probability that the host key is the same, not guaranteed proof.

     To get a listing of the fingerprints along with their random art for all known hosts, the follow‐
     ing command line can be used:

           $ ssh-keygen -lv -f ~/.ssh/known_hosts

     If the fingerprint is unknown, an alternative method of verification is available: SSH finger‐
     prints verified by DNS.  An additional resource record (RR), SSHFP, is added to a zonefile and the
     connecting client is able to match the fingerprint with that of the key presented.

     In this example, we are connecting a client to a server, “host.example.com”.  The SSHFP resource
     records should first be added to the zonefile for host.example.com:

           $ ssh-keygen -r host.example.com.

     The output lines will have to be added to the zonefile.  To check that the zone is answering fin‐
     gerprint queries:

           $ dig -t SSHFP host.example.com

     Finally the client connects:

           $ ssh -o "VerifyHostKeyDNS ask" host.example.com
           [...]
           Matching host key fingerprint found in DNS.
           Are you sure you want to continue connecting (yes/no)?

     See the VVeerriiffyyHHoossttKKeeyyDDNNSS option in ssh_config(5) for more information.

SSSSHH--BBAASSEEDD VVIIRRTTUUAALL PPRRIIVVAATTEE NNEETTWWOORRKKSS
     sssshh contains support for Virtual Private Network (VPN) tunnelling using the tun(4) network pseudo-
     device, allowing two networks to be joined securely.  The sshd_config(5) configuration option
     PPeerrmmiittTTuunnnneell controls whether the server supports this, and at what level (layer 2 or 3 traffic).

     The following example would connect client network 10.0.50.0/24 with remote network 10.0.99.0/24
     using a point-to-point connection from 10.1.1.1 to 10.1.1.2, provided that the SSH server running
     on the gateway to the remote network, at 192.168.1.15, allows it.

     On the client:

           # ssh -f -w 0:1 192.168.1.15 true
           # ifconfig tun0 10.1.1.1 10.1.1.2 netmask 255.255.255.252
           # route add 10.0.99.0/24 10.1.1.2

     On the server:

           # ifconfig tun1 10.1.1.2 10.1.1.1 netmask 255.255.255.252
           # route add 10.0.50.0/24 10.1.1.1

     Client access may be more finely tuned via the _/_r_o_o_t_/_._s_s_h_/_a_u_t_h_o_r_i_z_e_d___k_e_y_s file (see below) and the
     PPeerrmmiittRRoooottLLooggiinn server option.  The following entry would permit connections on tun(4) device 1
     from user “jane” and on tun device 2 from user “john”, if PPeerrmmiittRRoooottLLooggiinn is set to
     “forced-commands-only”:

       tunnel="1",command="sh /etc/netstart tun1" ssh-rsa ... jane
       tunnel="2",command="sh /etc/netstart tun2" ssh-rsa ... john

     Since an SSH-based setup entails a fair amount of overhead, it may be more suited to temporary
     setups, such as for wireless VPNs.  More permanent VPNs are better provided by tools such as
     ipsecctl(8) and isakmpd(8).

EENNVVIIRROONNMMEENNTT
     sssshh will normally set the following environment variables:

     DISPLAY               The DISPLAY variable indicates the location of the X11 server.  It is auto‐
                           matically set by sssshh to point to a value of the form “hostname:n”, where
                           “hostname” indicates the host where the shell runs, and ‘n’ is an integer ≥
                           1.  sssshh uses this special value to forward X11 connections over the secure
                           channel.  The user should normally not set DISPLAY explicitly, as that will
                           render the X11 connection insecure (and will require the user to manually
                           copy any required authorization cookies).

     HOME                  Set to the path of the user's home directory.

     LOGNAME               Synonym for USER; set for compatibility with systems that use this variable.

     MAIL                  Set to the path of the user's mailbox.

     PATH                  Set to the default PATH, as specified when compiling sssshh.

     SSH_ASKPASS           If sssshh needs a passphrase, it will read the passphrase from the current ter‐
                           minal if it was run from a terminal.  If sssshh does not have a terminal asso‐
                           ciated with it but DISPLAY and SSH_ASKPASS are set, it will execute the pro‐
                           gram specified by SSH_ASKPASS and open an X11 window to read the passphrase.
                           This is particularly useful when calling sssshh from a _._x_s_e_s_s_i_o_n or related
                           script.  (Note that on some machines it may be necessary to redirect the
                           input from _/_d_e_v_/_n_u_l_l to make this work.)

     SSH_AUTH_SOCK         Identifies the path of a UNIX-domain socket used to communicate with the
                           agent.

     SSH_CONNECTION        Identifies the client and server ends of the connection.  The variable con‐
                           tains four space-separated values: client IP address, client port number,
                           server IP address, and server port number.

     SSH_ORIGINAL_COMMAND  This variable contains the original command line if a forced command is exe‐
                           cuted.  It can be used to extract the original arguments.

     SSH_TTY               This is set to the name of the tty (path to the device) associated with the
                           current shell or command.  If the current session has no tty, this variable
                           is not set.

     TZ                    This variable is set to indicate the present time zone if it was set when
                           the daemon was started (i.e. the daemon passes the value on to new connec‐
                           tions).

     USER                  Set to the name of the user logging in.

     Additionally, sssshh reads _~_/_._s_s_h_/_e_n_v_i_r_o_n_m_e_n_t, and adds lines of the format “VARNAME=value” to the
     environment if the file exists and users are allowed to change their environment.  For more infor‐
     mation, see the PPeerrmmiittUUsseerrEEnnvviirroonnmmeenntt option in sshd_config(5).

FFIILLEESS
     ~/.rhosts
             This file is used for host-based authentication (see above).  On some machines this file
             may need to be world-readable if the user's home directory is on an NFS partition, because
             sshd(8) reads it as root.  Additionally, this file must be owned by the user, and must not
             have write permissions for anyone else.  The recommended permission for most machines is
             read/write for the user, and not accessible by others.

     ~/.shosts
             This file is used in exactly the same way as _._r_h_o_s_t_s, but allows host-based authentication
             without permitting login with rlogin/rsh.

     ~/.ssh/
             This directory is the default location for all user-specific configuration and authentica‐
             tion information.  There is no general requirement to keep the entire contents of this
             directory secret, but the recommended permissions are read/write/execute for the user, and
             not accessible by others.

     ~/.ssh/authorized_keys
             Lists the public keys (DSA, ECDSA, Ed25519, RSA) that can be used for logging in as this
             user.  The format of this file is described in the sshd(8) manual page.  This file is not
             highly sensitive, but the recommended permissions are read/write for the user, and not
             accessible by others.

     ~/.ssh/config
             This is the per-user configuration file.  The file format and configuration options are
             described in ssh_config(5).  Because of the potential for abuse, this file must have
             strict permissions: read/write for the user, and not writable by others.  It may be group-
             writable provided that the group in question contains only the user.

     ~/.ssh/environment
             Contains additional definitions for environment variables; see _E_N_V_I_R_O_N_M_E_N_T, above.

     ~/.ssh/id_dsa
     ~/.ssh/id_ecdsa
     ~/.ssh/id_ed25519
     ~/.ssh/id_rsa
             Contains the private key for authentication.  These files contain sensitive data and
             should be readable by the user but not accessible by others (read/write/execute).  sssshh
             will simply ignore a private key file if it is accessible by others.  It is possible to
             specify a passphrase when generating the key which will be used to encrypt the sensitive
             part of this file using 3DES.

     ~/.ssh/id_dsa.pub
     ~/.ssh/id_ecdsa.pub
     ~/.ssh/id_ed25519.pub
     ~/.ssh/id_rsa.pub
             Contains the public key for authentication.  These files are not sensitive and can (but
             need not) be readable by anyone.

     ~/.ssh/known_hosts
             Contains a list of host keys for all hosts the user has logged into that are not already
             in the systemwide list of known host keys.  See sshd(8) for further details of the format
             of this file.

     ~/.ssh/rc
             Commands in this file are executed by sssshh when the user logs in, just before the user's
             shell (or command) is started.  See the sshd(8) manual page for more information.

     /etc/hosts.equiv
             This file is for host-based authentication (see above).  It should only be writable by
             root.

     /etc/ssh/shosts.equiv
             This file is used in exactly the same way as _h_o_s_t_s_._e_q_u_i_v, but allows host-based authenti‐
             cation without permitting login with rlogin/rsh.

     /etc/ssh/ssh_config
             Systemwide configuration file.  The file format and configuration options are described in
             ssh_config(5).

     /etc/ssh/ssh_host_key
     /etc/ssh/ssh_host_dsa_key
     /etc/ssh/ssh_host_ecdsa_key
     /etc/ssh/ssh_host_ed25519_key
     /etc/ssh/ssh_host_rsa_key
             These files contain the private parts of the host keys and are used for host-based authen‐
             tication.

     /etc/ssh/ssh_known_hosts
             Systemwide list of known host keys.  This file should be prepared by the system adminis‐
             trator to contain the public host keys of all machines in the organization.  It should be
             world-readable.  See sshd(8) for further details of the format of this file.

     /etc/ssh/sshrc
             Commands in this file are executed by sssshh when the user logs in, just before the user's
             shell (or command) is started.  See the sshd(8) manual page for more information.

EEXXIITT SSTTAATTUUSS
     sssshh exits with the exit status of the remote command or with 255 if an error occurred.

SSEEEE AALLSSOO
     scp(1), sftp(1), ssh-add(1), ssh-agent(1), ssh-argv0(1), ssh-keygen(1), ssh-keyscan(1), tun(4),
     ssh_config(5), ssh-keysign(8), sshd(8)

SSTTAANNDDAARRDDSS
     S. Lehtinen and C. Lonvick, _T_h_e _S_e_c_u_r_e _S_h_e_l_l _(_S_S_H_) _P_r_o_t_o_c_o_l _A_s_s_i_g_n_e_d _N_u_m_b_e_r_s, RFC 4250, January
     2006.

     T. Ylonen and C. Lonvick, _T_h_e _S_e_c_u_r_e _S_h_e_l_l _(_S_S_H_) _P_r_o_t_o_c_o_l _A_r_c_h_i_t_e_c_t_u_r_e, RFC 4251, January 2006.

     T. Ylonen and C. Lonvick, _T_h_e _S_e_c_u_r_e _S_h_e_l_l _(_S_S_H_) _A_u_t_h_e_n_t_i_c_a_t_i_o_n _P_r_o_t_o_c_o_l, RFC 4252, January 2006.

     T. Ylonen and C. Lonvick, _T_h_e _S_e_c_u_r_e _S_h_e_l_l _(_S_S_H_) _T_r_a_n_s_p_o_r_t _L_a_y_e_r _P_r_o_t_o_c_o_l, RFC 4253, January 2006.

     T. Ylonen and C. Lonvick, _T_h_e _S_e_c_u_r_e _S_h_e_l_l _(_S_S_H_) _C_o_n_n_e_c_t_i_o_n _P_r_o_t_o_c_o_l, RFC 4254, January 2006.

     J. Schlyter and W. Griffin, _U_s_i_n_g _D_N_S _t_o _S_e_c_u_r_e_l_y _P_u_b_l_i_s_h _S_e_c_u_r_e _S_h_e_l_l _(_S_S_H_) _K_e_y _F_i_n_g_e_r_p_r_i_n_t_s, RFC
     4255, January 2006.

     F. Cusack and M. Forssen, _G_e_n_e_r_i_c _M_e_s_s_a_g_e _E_x_c_h_a_n_g_e _A_u_t_h_e_n_t_i_c_a_t_i_o_n _f_o_r _t_h_e _S_e_c_u_r_e _S_h_e_l_l _P_r_o_t_o_c_o_l
     _(_S_S_H_), RFC 4256, January 2006.

     J. Galbraith and P. Remaker, _T_h_e _S_e_c_u_r_e _S_h_e_l_l _(_S_S_H_) _S_e_s_s_i_o_n _C_h_a_n_n_e_l _B_r_e_a_k _E_x_t_e_n_s_i_o_n, RFC 4335,
     January 2006.

     M. Bellare, T. Kohno, and C. Namprempre, _T_h_e _S_e_c_u_r_e _S_h_e_l_l _(_S_S_H_) _T_r_a_n_s_p_o_r_t _L_a_y_e_r _E_n_c_r_y_p_t_i_o_n _M_o_d_e_s,
     RFC 4344, January 2006.

     B. Harris, _I_m_p_r_o_v_e_d _A_r_c_f_o_u_r _M_o_d_e_s _f_o_r _t_h_e _S_e_c_u_r_e _S_h_e_l_l _(_S_S_H_) _T_r_a_n_s_p_o_r_t _L_a_y_e_r _P_r_o_t_o_c_o_l, RFC 4345,
     January 2006.

     M. Friedl, N. Provos, and W. Simpson, _D_i_f_f_i_e_-_H_e_l_l_m_a_n _G_r_o_u_p _E_x_c_h_a_n_g_e _f_o_r _t_h_e _S_e_c_u_r_e _S_h_e_l_l _(_S_S_H_)
     _T_r_a_n_s_p_o_r_t _L_a_y_e_r _P_r_o_t_o_c_o_l, RFC 4419, March 2006.

     J. Galbraith and R. Thayer, _T_h_e _S_e_c_u_r_e _S_h_e_l_l _(_S_S_H_) _P_u_b_l_i_c _K_e_y _F_i_l_e _F_o_r_m_a_t, RFC 4716, November
     2006.

     D. Stebila and J. Green, _E_l_l_i_p_t_i_c _C_u_r_v_e _A_l_g_o_r_i_t_h_m _I_n_t_e_g_r_a_t_i_o_n _i_n _t_h_e _S_e_c_u_r_e _S_h_e_l_l _T_r_a_n_s_p_o_r_t _L_a_y_e_r,
     RFC 5656, December 2009.

     A. Perrig and D. Song, _H_a_s_h _V_i_s_u_a_l_i_z_a_t_i_o_n_: _a _N_e_w _T_e_c_h_n_i_q_u_e _t_o _i_m_p_r_o_v_e _R_e_a_l_-_W_o_r_l_d _S_e_c_u_r_i_t_y, 1999,
     International Workshop on Cryptographic Techniques and E-Commerce (CrypTEC '99).

AAUUTTHHOORRSS
     OpenSSH is a derivative of the original and free ssh 1.2.12 release by Tatu Ylonen.  Aaron Camp‐
     bell, Bob Beck, Markus Friedl, Niels Provos, Theo de Raadt and Dug Song removed many bugs, re-
     added newer features and created OpenSSH.  Markus Friedl contributed the support for SSH protocol
     versions 1.5 and 2.0.

BSD                                        September 21, 2017                                       BSD
