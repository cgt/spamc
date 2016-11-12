// Package spamc provides a client for the SpamAssassin spamd protocol.
// http://svn.apache.org/repos/asf/spamassassin/trunk/spamd/PROTOCOL
package spamc

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const ProtoVersion = "1.5"

var (
	spamInfoRe    = regexp.MustCompile(`(.+)\/(.+) (\d+) (.+)`)
	spamMainRe    = regexp.MustCompile(`^Spam: (.+) ; (.+) . (.+)$`)
	spamDetailsRe = regexp.MustCompile(`^(-?[0-9\.]*)\s([a-zA-Z0-9_]*)(\W*)([\w:\s-]*)`)
)

// connection is like net.Conn except that it also has a CloseWrite method.
// CloseWrite is implemented by net.TCPConn and net.UnixConn, but for some
// reason it is not present in the net.Conn interface.
type connection interface {
	net.Conn
	CloseWrite() error
}

// Client is a spamd client.
type Client struct {
	net  string
	addr string
}

// NewTCP returns a *Client that connects to spamd via the given TCP address.
func NewTCP(addr string) *Client {
	return &Client{"tcp", addr}
}

// NewTCP returns a *Client that connects to spamd via the given Unix socket.
func NewUnix(addr string) *Client {
	return &Client{"unix", addr}
}

// Header represents a matched SpamAssassin rule.
type Header struct {
	Points      string
	RuleName    string
	Description string
}

type Result struct {
	ResponseCode int
	Message      string
	Spam         bool
	Score        float64
	Threshold    float64
	Details      []Header
}

// dial connects to spamd through TCP or a Unix socket.
func (c *Client) dial() (connection, error) {
	if c.net == "tcp" {
		tcpAddr, err := net.ResolveTCPAddr("tcp", c.addr)
		if err != nil {
			return nil, err
		}
		return net.DialTCP("tcp", nil, tcpAddr)
	} else if c.net == "unix" {
		unixAddr, err := net.ResolveUnixAddr("unix", c.addr)
		if err != nil {
			return nil, err
		}
		return net.DialUnix("unix", nil, unixAddr)
	}
	panic("Client.net must be either \"tcp\" or \"unix\"")
}

// Report checks if message is spam or not, and returns score plus report
func (c *Client) Report(email []byte) (Result, error) {
	output, err := c.report(email)
	if err != nil {
		return Result{}, err
	}
	return c.parseOutput(output), nil
}

func (c *Client) report(email []byte) ([]string, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	bw := bufio.NewWriter(conn)
	_, err = bw.WriteString("REPORT SPAMC/" + ProtoVersion + "\r\n")
	if err != nil {
		return nil, err
	}
	_, err = bw.WriteString("Content-length: " + strconv.Itoa(len(email)) + "\r\n\r\n")
	if err != nil {
		return nil, err
	}
	_, err = bw.Write(email)
	if err != nil {
		return nil, err
	}
	err = bw.Flush()
	if err != nil {
		return nil, err
	}
	// Client is supposed to close its writing side of the connection
	// after sending its request.
	err = conn.CloseWrite()
	if err != nil {
		return nil, err
	}

	var (
		dataArrays []string
		br         = bufio.NewReader(conn)
	)
	for {
		line, err := br.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, " \t\r\n")
		dataArrays = append(dataArrays, line)
	}

	return dataArrays, nil
}

func (c *Client) parseOutput(output []string) Result {
	var result Result
	for _, row := range output {
		// header
		if spamInfoRe.MatchString(row) {
			res := spamInfoRe.FindStringSubmatch(row)
			if len(res) == 5 {
				resCode, err := strconv.Atoi(res[3])
				if err == nil {
					result.ResponseCode = resCode
				}
				result.Message = res[4]
			}
		}
		// summary
		if spamMainRe.MatchString(row) {
			res := spamMainRe.FindStringSubmatch(row)
			if len(res) == 4 {
				if strings.ToLower(res[1]) == "true" || strings.ToLower(res[1]) == "yes" {
					result.Spam = true
				} else {
					result.Spam = false
				}
				resFloat, err := strconv.ParseFloat(res[2], 64)
				if err == nil {
					result.Score = resFloat
				}
				resFloat, err = strconv.ParseFloat(res[3], 64)
				if err == nil {
					result.Threshold = resFloat
				}
			}
		}
		// details
		row = strings.Trim(row, " \t\r\n")
		if spamDetailsRe.MatchString(row) {
			res := spamDetailsRe.FindStringSubmatch(row)
			if len(res) == 5 {
				header := Header{Points: res[1], RuleName: res[2], Description: res[4]}
				result.Details = append(result.Details, header)
			}
		}
	}
	return result
}

func (c *Client) Ping() error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = io.WriteString(conn, fmt.Sprintf("PING SPAMC/%s\r\n\r\n", ProtoVersion))
	if err != nil {
		return err
	}
	err = conn.CloseWrite()
	if err != nil {
		return err
	}

	br := bufio.NewReader(conn)
	for {
		_, err = br.ReadSlice('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}
