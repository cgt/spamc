// Package spamc provides a client for the SpamAssassin spamd protocol.
// http://svn.apache.org/repos/asf/spamassassin/trunk/spamd/PROTOCOL
package spamc

import (
	"bufio"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	spamInfoRe    = regexp.MustCompile(`(.+)\/(.+) (\d+) (.+)`)
	spamMainRe    = regexp.MustCompile(`^Spam: (.+) ; (.+) . (.+)$`)
	spamDetailsRe = regexp.MustCompile(`^(-?[0-9\.]*)\s([a-zA-Z0-9_]*)(\W*)([\w:\s-]*)`)
)

type Client struct {
	Addr string
}

type Header struct {
	Pts         string
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

func (c *Client) CheckEmail(email []byte) (Result, error) {
	output, err := c.checkEmail(email)
	if err != nil {
		return Result{}, err
	}
	return c.parseOutput(output), nil
}

func (c *Client) checkEmail(email []byte) ([]string, error) {
	host, port, err := net.SplitHostPort(c.Addr)
	if err != nil {
		return nil, err
	}
	intport, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	addr := &net.TCPAddr{
		IP:   net.ParseIP(host),
		Port: intport,
	}
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	bw := bufio.NewWriter(conn)
	_, err = bw.WriteString("REPORT SPAMC/1.2\r\n")
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
				header := Header{Pts: res[1], RuleName: res[2], Description: res[4]}
				result.Details = append(result.Details, header)
			}
		}
	}
	return result
}
