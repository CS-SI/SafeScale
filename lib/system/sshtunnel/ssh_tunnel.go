/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sshtunnel

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/sanity-io/litter"
	"golang.org/x/crypto/ssh"
)

type logger interface {
	Printf(string, ...interface{})
}

type extendedLogger interface {
	Printf(string, ...interface{})
	Errorf(string, ...interface{})
}

type dumper interface { // nolint
	Dump() string
}

func OnPanic(err *error) func() {
	return func() {
		if x := recover(); x != nil {
			if anError, ok := x.(error); ok {
				*err = fmt.Errorf("runtime panic occurred: %w", anError)
			} else {
				*err = fmt.Errorf("runtime panic occurred: %v", x)
			}
		}
	}
}

type Option func(tunnel *SSHTunnel) error

type SSHTunnel struct {
	local  *Entrypoint
	server *SSHJump // a.k.a the gateway, or the jump
	remote *Endpoint

	config *ssh.ClientConfig

	tid uuid.UUID // tunnel id
	log logger

	conns       []net.Conn
	serverConns []*ssh.Client

	dialTimeout       time.Duration
	timeTunnelRunning time.Duration

	withKeepAlive      bool
	timeKeepAliveRead  time.Duration
	timeKeepAliveWrite time.Duration

	cleanupDelay time.Duration

	isOpen bool

	closer   chan interface{}
	closerFw chan interface{}

	ready chan bool

	inBuffer  []byte
	outBuffer []byte

	command string
	mu      *sync.Mutex
}

func (tunnel *SSHTunnel) logf(sfmt string, args ...interface{}) {
	if tunnel.log != nil {
		tunnel.log.Printf(fmt.Sprintf("[tunnel:%s] ", tunnel.tid.String())+sfmt, args...)
	}
}

func (tunnel *SSHTunnel) errorf(sfmt string, args ...interface{}) {
	if tunnel.log != nil {
		if eLog, ok := tunnel.log.(extendedLogger); ok {
			eLog.Errorf(fmt.Sprintf("[tunnel:%s] ", tunnel.tid.String())+sfmt, args...)
		} else {
			tunnel.log.Printf(fmt.Sprintf("[tunnel:%s] ", tunnel.tid.String())+sfmt, args...)
		}
	}
}

func (tunnel SSHTunnel) GetLocalEndpoint() Endpoint {
	tunnel.mu.Lock()
	defer tunnel.mu.Unlock()
	return *(tunnel.local)
}

func (tunnel SSHTunnel) GetRemoteEndpoint() Endpoint {
	tunnel.mu.Lock()
	defer tunnel.mu.Unlock()
	return *(tunnel.remote)
}

func (tunnel SSHTunnel) GetServerEndpoint() Endpoint {
	tunnel.mu.Lock()
	defer tunnel.mu.Unlock()
	return *(tunnel.server)
}

func (tunnel *SSHTunnel) SetCommand(cmd string) {
	tunnel.command = cmd
}

func (tunnel *SSHTunnel) newConnectionWaiter(listener net.Listener, c chan net.Conn) (err error) {
	defer OnPanic(&err)
	conn, err := listener.Accept()
	if err != nil {
		err = convertErrorToTunnelError(err)
		return fmt.Errorf("error in listener waiting for a connection: %w", err)
	}
	if tunnel.withKeepAlive {
		conn, _ = setConnectionDeadlines(conn, tunnel.timeKeepAliveRead, tunnel.timeKeepAliveWrite)
	}
	c <- conn
	return nil
}

func (tunnel *SSHTunnel) netListenWithTimeout(network, address string, timeout time.Duration) (
	_ net.Listener, err error,
) {
	defer OnPanic(&err)

	type result struct {
		resLis net.Listener
		resErr error
	}

	resChan := make(chan result)
	go func() {
		var crash error
		defer OnPanic(&crash)

		theCli, theErr := net.Listen(network, address)
		if theErr != nil {
			litter.Config.HidePrivateFields = false
			tunnel.errorf("netListenWithTimeout failed: netErr: %s", litter.Sdump(theErr))
		}
		defer close(resChan)
		resChan <- result{
			resLis: theCli,
			resErr: theErr,
		}
		return // nolint
	}()

	if timeout != 0 {
		select {
		case res := <-resChan:
			return res.resLis, res.resErr
		case <-time.After(timeout):
			return nil, tunnelError{
				error:       fmt.Errorf(fmt.Sprintf("timeout of %s listening", timeout)),
				isTimeout:   true,
				isTemporary: false,
			}
		}
	}

	res := <-resChan
	return res.resLis, res.resErr
}

func (tunnel *SSHTunnel) Ready() <-chan bool {
	return tunnel.ready
}

func (tunnel *SSHTunnel) Start() (err error) {
	defer OnPanic(&err)

	tunnel.mu.Lock()
	if tunnel.isOpen {
		defer tunnel.mu.Unlock()
		return fmt.Errorf("error starting the ssh tunnel: already started")
	}

	listener, err := tunnel.netListenWithTimeout("tcp", tunnel.local.Address(), tunnel.dialTimeout)
	if err != nil {
		defer tunnel.mu.Unlock()
		err = convertErrorToTunnelError(err)
		tunnel.ready <- false
		close(tunnel.ready)
		return fmt.Errorf("error starting the ssh tunnel: %w", err)
	}

	tunnel.isOpen = true
	if tunnel.local.Port() == 0 {
		tcpAddr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			defer tunnel.mu.Unlock()
			return fmt.Errorf("failure casting to *net.TCPAddr")
		}
		tunnel.local.port = tcpAddr.Port
	}
	tunnel.mu.Unlock() // nolint

	defer func() {
		tunnel.closerFw <- struct{}{}
		close(tunnel.closerFw)
	}()

	defer func(st time.Time) {
		tunnel.timeTunnelRunning = time.Since(st)
		tunnel.logf("ssh tunnel lifetime (%s): %s", tunnel.command, tunnel.timeTunnelRunning)
	}(time.Now())

	var quittingErr error

	for {
		if !tunnel.isOpen {
			break
		}

		errCh := make(chan error)
		connCh := make(chan net.Conn)
		go func() {
			var crash error
			defer OnPanic(&crash)

			cwErr := tunnel.newConnectionWaiter(listener, connCh)
			if cwErr != nil {
				cwErr = convertErrorToTunnelError(cwErr)
				defer close(errCh)
				errCh <- cwErr
			}
			return // nolint
		}()

		tunnel.logf("listening for new ssh connections...")
		select {
		case <-tunnel.ready:
		default:
			tunnel.ready <- true
			close(tunnel.ready)
		}

		select {
		case werr := <-errCh:
			if werr != nil {
				tunnel.errorf("error received listening for new ssh connections: %v", werr)
			}
			continue
		case <-tunnel.closer:
			tunnel.logf("close signal received through channel: closing tunnel...\n")
			tunnel.isOpen = false
		case conn := <-connCh:
			tunnel.mu.Lock()
			tunnel.conns = append(tunnel.conns, conn)
			tunnel.mu.Unlock() // nolint
			tunnel.logf("accepted connection")
			go func() {
				var crash error
				defer OnPanic(&crash)

				var fwErr error
				for {
					fwErr = tunnel.forward(conn)
					if fwErr == nil {
						break
					}
					if netErr, ok := errors.Unwrap(fwErr).(tunnelError); ok {
						if netErr.Timeout() && netErr.Temporary() {
							continue
						}
						quittingErr = fwErr
						break
					}
					quittingErr = fwErr
					break
				}
				if quittingErr != nil {
					litter.Config.HidePrivateFields = false
					tunnel.errorf("closing tunnel due to failure forwarding tunnel: %s", litter.Sdump(quittingErr))
					tunnel.Close()
				}
				return // nolint
			}()
		}
	}

	total := len(tunnel.conns) + len(tunnel.serverConns) + 1
	for i, conn := range tunnel.conns {
		tunnel.logf("[%d/%d] closing the netConn", i+1, total)
		err := conn.Close()
		if err != nil {
			err = convertErrorToTunnelError(err)
			litter.Config.HidePrivateFields = false
			tunnel.errorf("error closing the connection: %s", litter.Sdump(err))
		}
	}

	for i, conn := range tunnel.serverConns {
		tunnel.logf("[%d/%d] closing the serverConn", i+len(tunnel.conns)+1, total)
		err := conn.Close()
		if err != nil {
			err = convertErrorToTunnelError(err)
			litter.Config.HidePrivateFields = false
			tunnel.errorf("error closing the server connection: %s", litter.Sdump(err))
		}
	}

	tunnel.logf("[%d/%d] closing the listener", total, total)
	err = listener.Close()
	if err != nil {
		err = convertErrorToTunnelError(err)
		return fmt.Errorf("error closing the listener: %w", err)
	}

	if quittingErr != nil {
		litter.Config.HidePrivateFields = false
		tunnel.errorf("tunnel closed due to error: %s", litter.Sdump(quittingErr))
	} else {
		tunnel.logf("tunnel closed")
	}

	return quittingErr
}

func TunnelOptionWithDialTimeout(timeout time.Duration) Option {
	return func(tunnel *SSHTunnel) error {
		tunnel.dialTimeout = timeout
		return nil
	}
}

func TunnelOptionWithKeepAlive(keepAlive time.Duration) Option {
	return func(tunnel *SSHTunnel) error {
		tunnel.withKeepAlive = true
		tunnel.timeKeepAliveRead = keepAlive
		tunnel.timeKeepAliveWrite = keepAlive
		return nil
	}
}

func TunnelOptionWithDefaultKeepAlive() Option {
	return func(tunnel *SSHTunnel) error {
		tunnel.withKeepAlive = true

		kal := newDefaultKeepAliveCfg()
		tunnel.timeKeepAliveRead = time.Duration(kal.tcpKeepaliveTime) * time.Second
		tunnel.timeKeepAliveWrite = time.Duration(kal.tcpKeepaliveTime) * time.Second
		return nil
	}
}

func TunnelOptionWithLogger(myLogger logger) Option {
	return func(tunnel *SSHTunnel) error {
		tunnel.log = myLogger
		return nil
	}
}

func (tunnel *SSHTunnel) dialSSHWithTimeout(
	network, addr string, config *ssh.ClientConfig, timeout time.Duration,
) (_ *ssh.Client, err error) {
	defer OnPanic(&err)

	type result struct {
		resCli *ssh.Client
		resErr error
	}

	resChan := make(chan result)
	go func() {
		var crash error
		defer OnPanic(&crash)

		theCli, theErr := sshDial(network, addr, config)
		if theErr != nil {
			litter.Config.HidePrivateFields = false
			tunnel.errorf("dialSSHWithTimeout failed: netErr: %s", litter.Sdump(theErr))
		}
		defer close(resChan)
		resChan <- result{
			resCli: theCli,
			resErr: theErr,
		}
		return // nolint
	}()

	if timeout != 0 {
		select {
		case res := <-resChan:
			return res.resCli, res.resErr
		case <-time.After(timeout):
			return nil, tunnelError{
				error:       fmt.Errorf(fmt.Sprintf("timeout of %s dialing", timeout)),
				isTimeout:   true,
				isTemporary: false,
			}
		}
	}

	res := <-resChan
	return res.resCli, res.resErr
}

func (tunnel *SSHTunnel) dialSSHConnectionWithTimeout(
	cli *ssh.Client, n, addr string, timeout time.Duration,
) (_ net.Conn, err error) {
	defer OnPanic(&err)

	type result struct {
		resConn net.Conn
		resErr  error
	}

	expired := false

	resChan := make(chan result)
	go func() {
		var crash error
		defer OnPanic(&crash)

		theConn, theErr := cli.Dial(n, addr)
		if theErr != nil {
			litter.Config.HidePrivateFields = false
			tunnel.errorf("dialSSHConnectionWithTimeout failed: netErr: %s", litter.Sdump(theErr))
			theErr = convertErrorToTunnelError(theErr)
			if !expired {
				if theErr != nil {
					tunnel.errorf("dial error with timeout of %s: %s", timeout, litter.Sdump(theErr))
				}
			}
		}
		defer close(resChan)
		resChan <- result{
			resConn: theConn,
			resErr:  theErr,
		}
		return // nolint
	}()

	if timeout != 0 {
		select {
		case res := <-resChan:
			expired = true
			return res.resConn, res.resErr
		case <-time.After(timeout):
			expired = true
			return nil, tunnelError{
				error:       fmt.Errorf(fmt.Sprintf("timeout of %s dialing", timeout)),
				isTimeout:   true,
				isTemporary: false,
			}
		}
	}

	res := <-resChan
	expired = true
	return res.resConn, res.resErr
}

func (tunnel *SSHTunnel) forward(localConn net.Conn) (err error) {
	defer OnPanic(&err)

	tunnel.logf("[1/4] dialing %s with timeout of %s\n", tunnel.server.String(), tunnel.dialTimeout)
	dialOp := time.Now()
	serverConn, err := tunnel.dialSSHWithTimeout("tcp", tunnel.server.Address(), tunnel.config, tunnel.dialTimeout)
	if err != nil {
		err = convertErrorToTunnelError(err)
		tunnel.errorf("server dial error to '%s': %s", tunnel.server.String(), litter.Sdump(err))
		return fmt.Errorf("server dial error to '%s': %w", tunnel.server.String(), err)
	}
	tunnel.serverConns = append(tunnel.serverConns, serverConn)
	tunnel.logf("[2/4] dialed %s in %s\n", tunnel.server.String(), time.Since(dialOp))
	dialOp = time.Now()
	tunnel.logf("[3/4] dialing %s with timeout of %s\n", tunnel.remote.String(), tunnel.dialTimeout)

	// FIXME: Put everything between lock and unlock in a function
	tunnel.mu.Lock()
	remoteConn, err := tunnel.dialSSHConnectionWithTimeout(serverConn, "tcp", tunnel.remote.Address(), tunnel.dialTimeout)
	if err != nil {
		defer tunnel.mu.Unlock()
		err = convertErrorToTunnelError(err)
		tunnel.errorf("remote dial error, unable to reach %s: %s", tunnel.remote.String(), litter.Sdump(err))
		return fmt.Errorf("remote dial error, unable to reach %s: %w", tunnel.remote.String(), err)
	}
	if tunnel.withKeepAlive {
		remoteConn, _ = setConnectionDeadlines(remoteConn, tunnel.timeKeepAliveRead, tunnel.timeKeepAliveWrite)
	}
	tunnel.conns = append(tunnel.conns, remoteConn)
	tunnel.mu.Unlock() // nolint

	tunnel.logf("[4/4] dialed %s through %s in %s\n", tunnel.remote.String(), tunnel.local.String(), time.Since(dialOp))

	stopUpdown := make(chan struct{})
	updown := make(chan bool)
	copyConn := func(copier string, writer, reader net.Conn, buff *[]byte) {
		endCopy := make(chan bool)
		go func() {
			var crash error
			defer OnPanic(&crash)

			defer close(endCopy)
			_, err := io.CopyBuffer(writer, reader, *buff)
			if err != nil {
				report := true
				ignored := false
				if opErr, ok := err.(*net.OpError); ok {
					if strings.Contains(opErr.Err.Error(), "use of closed network connection") { // nolint
						report = false
						ignored = true
					}
				}
				if report {
					tunnel.errorf("io.Copy [%s] ended with error: %s", copier, litter.Sdump(err))
				}
				if ignored {
					tunnel.logf("io.Copy [%s] ended with warnings", copier)
				}
				endCopy <- false
				select {
				case <-tunnel.closerFw:
					return
				case <-stopUpdown:
					return
				default:
					updown <- true
				}
				return
			}
			tunnel.logf("io.Copy [%s] ended without error", copier)
			endCopy <- true
			select {
			case <-tunnel.closerFw:
				return
			case <-stopUpdown:
				return
			default:
				updown <- true
			}
			return // nolint
		}()
		select {
		case <-endCopy:
			return
		case <-stopUpdown:
			return
		case <-tunnel.closerFw:
			tunnel.logf("tunnel is closing, stopping copies")
			return
		}
	}

	// Both goroutines should end almost in the same second one after another, if not we can consider the tunnel dead...
	go func() {
		var crash error
		defer OnPanic(&crash)

		defer func() {
			close(stopUpdown)
			close(updown)
		}()

		minim := tunnel.cleanupDelay

		if tunnel.withKeepAlive {
			minim = tunnel.timeKeepAliveRead
			if minim > tunnel.timeKeepAliveWrite {
				minim = tunnel.timeKeepAliveWrite
			}
		}

		if minim == 0 || minim > 60 { // zero ain't valid
			minim = tunnel.cleanupDelay
			if minim == 0 || minim > 60 {
				minim = 15 * time.Second
			}
		}

		<-updown // Indeed, if both goroutines die, this one dies too
		tunnel.logf("first in, waiting for the second...")
		select {
		case <-updown:
			tunnel.logf("second there...")
			return
		case <-time.After(minim):
			select {
			case <-tunnel.closerFw:
				return
			default:
				tunnel.errorf("the tunnel is dead after %s (%s)...", minim, tunnel.command)
				// tunnel.Close() // if so, we have a use of closed connection error
				return
			}
		}
	}()

	go copyConn("upstream", localConn, remoteConn, &tunnel.inBuffer)
	go copyConn("downstream", remoteConn, localConn, &tunnel.outBuffer)

	return nil
}

func (tunnel *SSHTunnel) Close() {
	if tunnel.isOpen {
		tunnel.closer <- struct{}{}
		close(tunnel.closer)
	}
	return // nolint
}

func NewSSHTunnelFromCfg(gw SSHJump, target Endpoint, local Entrypoint, options ...Option) (_ *SSHTunnel, err error) {
	defer OnPanic(&err)

	gwCfg, err := convertToSSHClientConfig(&gw, 0)
	if err != nil {
		err = convertErrorToTunnelError(err)
		return nil, fmt.Errorf("wrong gateway configuration: %w", err)
	}

	return NewSSHTunnelWithLocalBinding(gw.String(), gwCfg.Auth[0], target.Address(), local.Address(), options...)
}

// NewSSHTunnel creates a ssh tunnel through localhost:0
func NewSSHTunnel(tunnel string, auth ssh.AuthMethod, destination string, options ...Option) (_ *SSHTunnel, err error) {
	return NewSSHTunnelWithLocalBinding(tunnel, auth, destination, "localhost:0", options...)
}

// NewSSHTunnelWithLocalBinding creates a ssh tunnel
func NewSSHTunnelWithLocalBinding(
	tunnel string, auth ssh.AuthMethod, destination string, source string, options ...Option,
) (_ *SSHTunnel, err error) {
	defer OnPanic(&err)

	localEndpoint, err := NewEndpoint(source)
	if err != nil {
		err = convertErrorToTunnelError(err)
		return nil, fmt.Errorf("error creating tunnel: %w", err)
	}

	server, err := NewEndpoint(tunnel, EndpointOptionAuth(auth))
	if err != nil {
		err = convertErrorToTunnelError(err)
		return nil, fmt.Errorf("error creating endpoint: %w", err)
	}
	if server.port == 0 {
		server.port = 22
	}

	remote, err := NewEndpoint(destination)
	if err != nil {
		err = convertErrorToTunnelError(err)
		return nil, fmt.Errorf("error creating remote endpoint: %w", err)
	}

	ttlCfg := newDefaultKeepAliveCfg()
	tid, err := uuid.NewV4()
	if err != nil {
		err = convertErrorToTunnelError(err)
		return nil, fmt.Errorf("error creating tunnel id: %w", err)
	}

	sshTunnel := &SSHTunnel{
		config: &ssh.ClientConfig{
			User: server.user,
			Auth: []ssh.AuthMethod{auth},
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				// Always accept key.
				return nil
			},
		},
		local:              localEndpoint,
		server:             server,
		remote:             remote,
		dialTimeout:        45 * time.Second,
		timeKeepAliveRead:  time.Duration(ttlCfg.tcpKeepaliveTime) * time.Second,
		timeKeepAliveWrite: time.Duration(ttlCfg.tcpKeepaliveTime) * time.Second,
		cleanupDelay:       15 * time.Second,
		closer:             make(chan interface{}),
		closerFw:           make(chan interface{}),
		ready:              make(chan bool),
		inBuffer:           make([]byte, int(math.Pow(2, 14))),
		outBuffer:          make([]byte, int(math.Pow(2, 14))),
		tid:                tid,
		mu:                 &sync.Mutex{},
	}

	for _, op := range options {
		if op != nil {
			err = op(sshTunnel)
			if err != nil {
				return nil, err
			}
		}
	}

	return sshTunnel, nil
}

func setConnectionDeadlines(in net.Conn, read time.Duration, write time.Duration) (net.Conn, bool) { // nolint
	var err error
	if tcpConn, ok := in.(*net.TCPConn); ok {
		failures := 0
		if err = in.SetReadDeadline(time.Now().Add(read)); err != nil {
			failures++
		}
		if err = in.SetWriteDeadline(time.Now().Add(write)); err != nil {
			failures++
		}

		if failures != 2 {
			return tcpConn, true
		}

		maxDeadLine := read
		if write > maxDeadLine {
			maxDeadLine = write
		}

		err = in.SetDeadline(time.Now().Add(maxDeadLine))
		if err != nil {
			failures++
		}

		if failures != 3 {
			return tcpConn, true
		}
	}

	return in, false
}
